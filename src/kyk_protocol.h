#ifndef KYK_PROTOCOL_H__
#define KYK_PROTOCOL_H__

#include "kyk_message.h"
#include "kyk_socket.h"

struct kyk_wallet;

int kyk_ptl_ping_req(const char* node,
		     const char* service,
		     ptl_message** rep_msg);


int kyk_ptl_pong_rep(int sockfd, ptl_message* ptl_msg);

int kyk_ptl_version_rep(int sockfd, ptl_message* req_msg);

int kyk_ptl_headers_rep(int sockfd,
			const ptl_message* req_msg,
			const struct kyk_blk_hd_chain* hd_chain);

int kyk_ptl_blk_rep(int sockfd,
		    const ptl_message* req_msg,
		    struct kyk_wallet* wallet);

#endif
