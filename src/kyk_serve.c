#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include "kyk_file.h"
#include "kyk_block.h"
#include "kyk_validate.h"
#include "kyk_utxo.h"
#include "kyk_address.h"
#include "kyk_wallet.h"
#include "kyk_message.h"
#include "kyk_sha.h"
#include "beej_pack.h"
#include "kyk_protocol.h"
#include "kyk_socket.h"
#include "dbg.h"

#define WALLET_NAME ".kyk_miner"

static int match_cmd(char *src, char *cmd);
static void sigchld_handler(int s);
static void *get_in_addr(struct sockaddr *sa);
static int load_wallet(struct kyk_wallet** wallet);


int kyk_start_serve(const char* host, const char* port)
{
    int sockfd, new_fd;                   /* listen on sock_fd, new connection on new_fd */
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;   /* connector's address information */
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    ptl_message* msg = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;         /* use my IP */

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return 1;
    }

    /* Loop through all the results and bind to the first we can */
    for(p = servinfo; p != NULL; p = p -> ai_next) {
	if ((sockfd = socket(p -> ai_family,
			     p -> ai_socktype,
			     p -> ai_protocol)) == -1) {
	    perror("server: socket");
	    continue;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
		       sizeof(int)) == -1) {
	    perror("setsockopt");
	    exit(1);
	}

	if (bind(sockfd, p -> ai_addr, p -> ai_addrlen) == -1) {
	    close(sockfd);
	    perror("server: bind");
	    continue;
	}

	break;
    }

    freeaddrinfo(servinfo); /* all done with this structure */

    if (p == NULL)  {
	fprintf(stderr, "server: failed to bind\n");
	exit(1);
    }

    if (listen(sockfd, KYK_SERVE_BACKLOG) == -1) {
	perror("listen");
	exit(1);
    }

    sa.sa_handler = sigchld_handler; /* reap all dead processes */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
	perror("sigaction");
	exit(1);
    }

    printf("server: waiting for connections in %s:%s\n", host, port);

    while(1) {  /* main accept() loop */
	sin_size = sizeof their_addr;
	new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
	if (new_fd == -1) {
	    perror("accept");
	    continue;
	}

	/* convert IPv4 and IPv6 addresses from binary to text form, s will store the converted result */
	inet_ntop(their_addr.ss_family,
		  get_in_addr((struct sockaddr *)&their_addr),
		  s, sizeof s);
	printf("server: got connection from %s\n", s);

	if (!fork()) {     /* this is the child process */
	    close(sockfd); /* child doesn't need the listener */
	    res = kyk_recv_ptl_msg(new_fd, &msg, KYK_PL_BUF_SIZE, NULL);
	    
	    if (res == -1){
		perror("recv");
	    } else {
		kyk_print_ptl_message(msg);
		if(match_cmd(msg -> cmd, KYK_MSG_TYPE_PING)){
		    res = kyk_ptl_pong_rep(new_fd, msg);
		    if(res == -1) perror("send");
		} else if(match_cmd(msg -> cmd, KYK_MSG_TYPE_VERSION)){
		    res = kyk_ptl_version_rep(new_fd, msg);
		    if(res == -1) perror("send");
		} else if(match_cmd(msg -> cmd, KYK_MSG_TYPE_GETHEADERS)){
		    res = load_wallet(&wallet);
		    res = kyk_load_blk_header_chain(&hd_chain, wallet);
		    check(res == 0, "Failed to kyk_load_blk_header_chain");
		    res = kyk_ptl_headers_rep(new_fd, msg, hd_chain);
		    /* check(res == 0, "Failed to kyk_ptl_headers_rep"); */
		} else if(match_cmd(msg -> cmd, KYK_MSG_TYPE_GETDATA)){
		    load_wallet(&wallet);
		    res = kyk_ptl_blk_rep(new_fd, msg, wallet);
		    /* check(res == 0, "Failed to kyk_ptl_blk_rep"); */
		} else if(match_cmd(msg -> cmd, KYK_MSG_TYPE_TX)){
		    load_wallet(&wallet);
		    res = kyk_ptl_tx_rep(new_fd, msg, wallet);
		} else {
		}
	    }
	    
	    close(new_fd);
	    exit(0);
	}
	close(new_fd);  // parent doesn't need this
    }

    return 0;

error:

    return -1;

}


void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
	return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int match_cmd(char *src, char *cmd)
{
    int res = 0;
    
    res = strcasecmp(src, cmd) == 0 ? 1 : 0;

    return res;
}

static int load_wallet(struct kyk_wallet** wallet)
{
    char *hmdir = NULL;
    char *wdir = NULL;

    hmdir = kyk_gethomedir();
    check(hmdir != NULL, "failed to find the current dir");
    wdir = kyk_pth_concat(hmdir, WALLET_NAME);
    check(wdir != NULL, "failed to find the wallet dir");

    *wallet = kyk_open_wallet(wdir);

    return 0;

error:
    
    return -1;

}


