#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "beej_pack.h"
#include "btc_message.h"


#define MAX_BUF_SIZE 1024

static size_t read_pld_len(const unsigned char *buf, size_t inx);

/* struct addrinfo { */
/*     int              ai_flags; */
/*     int              ai_family; */
/*     int              ai_socktype; */
/*     int              ai_protocol; */
/*     socklen_t        ai_addrlen; */
/*     struct sockaddr *ai_addr; */
/*     char            *ai_canonname; */
/*     struct addrinfo *ai_next; */
/* }; */

void kyk_send_btc_msg_buf(const char *node, const char *service, const ptl_msg_buf *msg_buf, ptl_resp_buf *resp_buf)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    size_t len;
    ssize_t nread;    
    unsigned char resp_body[MAX_BUF_SIZE];

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* any type socket, SOCK_STREAM  or  SOCK_DGRAM */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(node, service, &hints, &result);
    if (s != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
	exit(EXIT_FAILURE);
    }

/* getaddrinfo() returns a list of address structures.
   Try each address until we successfully connect(2).
   If socket(2) (or connect(2)) fails, we (close the socket
   and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
	sfd = socket(rp->ai_family,
		     rp->ai_socktype,
		     rp->ai_protocol);
	if (sfd == -1)
	    continue;

	if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1){
	    printf("connected success: %d\n", sfd);
	    break;                  /* Success */
	}

	close(sfd);
    }

    if (rp == NULL) {               /* No address succeeded */
	fprintf(stderr, "Could not connect\n");
	exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);           /* No longer needed */

    len = msg_buf -> len;
    if (len + 1> MAX_BUF_SIZE) {
	fprintf(stderr,
		"Ignoring long message\n");
	exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    printf("msg buf: ");
    for(int i=0; i < len; i++)
    {
	printf("%02x", msg_buf -> body[i]);
    }
    printf("\n");
#endif

    if (write(sfd, msg_buf -> body, len) != (ssize_t)len) {
	fprintf(stderr, "partial/failed write\n");
	exit(EXIT_FAILURE);
    }

    nread = recv(sfd, resp_body, MAX_BUF_SIZE-1, 0);
    if (nread == -1) {
	perror("read");
	exit(EXIT_FAILURE);
    }

    printf("Received %zd bytes\n", nread);
    resp_buf -> len = nread;
    // printf("%s\n", resp_body);
    /* for(int i=0; i < nread; i++){ */
    /* 	printf("%c", resp_body[i]); */
    /* } */

    memcpy(resp_buf -> body, resp_body, nread);


    //printf("\n");

}

ssize_t kyk_recv_btc_msg(int sockfd, ptl_msg_buf *msg_buf, size_t buf_len)
{
    unsigned char *bptr = msg_buf -> body;
    size_t recv_size = 0;
    size_t pld_size = 0;
    size_t msg_size = 24;
    int pld_flag = 1;
    
    while(1){
	ssize_t i = recv(sockfd, bptr, buf_len, 0);
	if(i == -1){
	    perror("recv");
	    break;
	}
	recv_size += i;
	bptr += i;
	if(recv_size >= 20 && pld_flag == 1){
	    pld_size = read_pld_len(msg_buf -> body, 16);
	    pld_flag = 0;
	}
	if(recv_size >= pld_size + msg_size){
	    break;
	}

    }

    if(recv_size < pld_size + msg_size){
	return -1;
    } else {
	msg_buf -> len = recv_size;
	msg_buf -> pld_len = pld_size;
	return recv_size;
    }

}

static size_t read_pld_len(const unsigned char *buf, size_t inx)
{
    uint32_t len = 0;
    
    buf += inx;
    beej_unpack(buf, "<L", &len);

    return (size_t)len;
}










