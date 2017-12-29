#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "beej_pack.h"
#include "kyk_message.h"
#include "kyk_socket.h"
#include "kyk_utils.h"
#include "dbg.h"


static uint32_t MAX_BUF_SIZE = 1000 * 1024;

static uint32_t read_pld_len(const unsigned char *buf, int pos);

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

int kyk_send_ptl_msg(const char* node,
		     const char* service,
		     const ptl_message* msg,
		     ptl_message** rep_msg)
{
    ptl_msg_buf* msg_buf = NULL;
    int res = -1;

    check(msg, "Failed to kyk_send_ptl_msg: msg is NULL");
    check(rep_msg, "Failed to kyk_send_ptl_msg: rep_msg is NULL");

    res = kyk_new_seri_ptl_message(&msg_buf, msg);
    check(res == 0, "Failed to kyk_send_ptlc_msg: kyk_new_seri_ptl_message failed");

    res = kyk_send_ptl_msg_buf(node, service, msg_buf, rep_msg);
    check(res == 0, "Failed to kyk_send_btc_msg");

    return 0;

error:

    return -1;
}

int kyk_send_ptl_msg_buf(const char *node,
			 const char *service,
			 const ptl_msg_buf* msg_buf,
			 ptl_message** new_rep_msg)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    size_t len;
    /* ssize_t nread; */
    /* ptl_resp_buf* resp_buf = NULL; */
    /* unsigned char resp_body[MAX_BUF_SIZE]; */
    ptl_message* rep_msg = NULL;
    int res = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* any type socket, SOCK_STREAM  or  SOCK_DGRAM */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(node, service, &hints, &result);
    check(s == 0, "Failed to kyk_send_btc_msg_buf: getaddrinfo: %s", gai_strerror(s));

   /*
   **  getaddrinfo() returns a list of address structures.
   **  Try each address until we successfully connect(2).
   **  If socket(2) (or connect(2)) fails, we (close the socket
   **  and) try the next address.
   */
    for (rp = result; rp != NULL; rp = rp -> ai_next) {
	sfd = socket(rp -> ai_family,
		     rp -> ai_socktype,
		     rp -> ai_protocol);
	if (sfd == -1)
	    continue;

	if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1){
	    printf("connected success: %d\n", sfd);
	    break;                  /* Success */
	}

	close(sfd);
    }

    check(rp, "Failed to kyk_send_btc_msg_buf: Could not connect");

    /* No longer needed */
    freeaddrinfo(result);           

    len = msg_buf -> len;
    if (len + 1 > MAX_BUF_SIZE) {
	fprintf(stderr, "Ignoring long message\n");
	exit(EXIT_FAILURE);
    }

    if (write(sfd, msg_buf -> data, len) != (ssize_t)len) {
	fprintf(stderr, "partial/failed write\n");
	exit(EXIT_FAILURE);
    }

    res = kyk_recv_ptl_msg(sfd, &rep_msg, KYK_PL_BUF_SIZE, NULL);
    check(res == 0, "Failed to kyk_send_btc_msg_buf: kyk_recv_ptl_msg failed");

    *new_rep_msg = rep_msg;

    close(sfd);
    
    return 0;

error:

    return -1;

}

int kyk_recv_ptl_msg(int sockfd, ptl_message** new_ptl_msg, size_t buf_len, size_t* checksize)
{
    ptl_message* ptl_msg = NULL;
    uint8_t* buf = NULL;
    uint8_t* larger_buf = NULL;
    uint8_t* bufp = NULL;
    size_t recv_len = 0;
    uint32_t pld_len = 0;
    int pld_flag = 1;
    int res = -1;

    check(new_ptl_msg, "Failed to kyk_recv_ptl_msg: new_ptl_msg is NULL");

    buf = calloc(buf_len, sizeof(*buf));
    check(buf, "Failed to kyk_recv_ptl_msg: calloc failed");

    bufp = buf;

    while(1){
	ssize_t i = recv(sockfd, bufp, buf_len, 0);
	if(i == -1){
	    perror("recv");
	    break;
	}
	recv_len += i;
	bufp += i;
	if(recv_len >= KYK_MSG_HEADER_LEN && pld_flag == 1){
	    pld_len = read_pld_len(buf, KYK_PLD_LEN_POS);
	    pld_flag = 0;
	}
	
	if(recv_len >= pld_len + KYK_MSG_HEADER_LEN){
	    break;
	}

	/* need to realloc a larger buffer */
	if(buf_len < pld_len + KYK_MSG_HEADER_LEN){
	    size_t total_len = pld_len + KYK_MSG_HEADER_LEN;
	    larger_buf = realloc(buf, total_len * sizeof(*buf));
	    check(larger_buf, "Failed to kyk_recv_ptl_msg: realloc failed");
	    buf = larger_buf;
	    bufp = buf + recv_len;
	}
        

    }

    check(recv_len >= pld_len + KYK_MSG_HEADER_LEN, "Failed to kyk_recv_ptl_msg: invalid received bytes len");

    res = kyk_deseri_new_ptl_message(&ptl_msg, buf, recv_len);
    check(res == 0, "Failed to kyk_recv_ptl_msg: kyk_deseri_new_ptl_message failed");

    *new_ptl_msg = ptl_msg;

    if(checksize){
	*checksize = recv_len;
    }

    free(buf);
	
    return 0;

error:
    if(buf) free(buf);
    if(ptl_msg) kyk_free_ptl_msg(ptl_msg);
    return -1;

}

int kyk_reply_ptl_msg(int sockfd, ptl_message* rep_msg)
{
    ptl_msg_buf* msg_buf = NULL;
    ssize_t sent_len = 0;
    int res = -1;

    check(rep_msg, "Failed to kyk_reply_ptl_msg: rep_msg is NULL");

    res = kyk_new_seri_ptl_message(&msg_buf, rep_msg);
    check(res == 0, "Failed to kyk_reply_ptl_msg: kyk_new_seri_ptl_message failed");
    
    sent_len = send(sockfd, msg_buf -> data, msg_buf -> len, 0);
    check(sent_len > 0, "Failed to kyk_reply_ptl_msg: send failed");

    return 0;

error:

    return -1;
}

uint32_t read_pld_len(const unsigned char *buf, int pos)
{
    uint32_t len = 0;
    
    buf += pos;
    beej_unpack(buf, "<L", &len);

    return len;
}










