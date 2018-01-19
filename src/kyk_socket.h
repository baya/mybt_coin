#ifndef KYK_SOCKET_H__
#define KYK_SOCKET_H__


int kyk_send_ptl_msg(const char* node,
		     const char* service,
		     const ptl_message* msg,
		     ptl_message** rep_msg);

int kyk_recv_ptl_msg(int sockfd,
		     ptl_message** new_ptl_msg,
		     size_t buf_len,
		     size_t* checksize);

int kyk_reply_ptl_msg(int sockfd, ptl_message* ptl_msg);



int kyk_send_ptl_msg_buf(const char *node,
			 const char *service,
			 const ptl_msg_buf* msg_buf,
			 ptl_message** new_rep_msg);

int kyk_socket_connect(const char* node, const char* service, int* socketid);

int kyk_write_ptl_msg(int sfd, const ptl_message* msg);

int kyk_write_msg_buf(int sfd, const ptl_msg_buf* msg_buf);
#endif
