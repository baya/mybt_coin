#ifndef KYK_SOCKET_H__
#define KYK_SOCKET_H__

void kyk_send_btc_msg_buf(const char *node, const char *service, const ptl_msg_buf *msg_buf, ptl_resp_buf *resp_buf);
int kyk_recv_btc_msg(int sockfd, ptl_msg_buf *msg_buf, size_t buf_len, size_t* checksize);

#endif
