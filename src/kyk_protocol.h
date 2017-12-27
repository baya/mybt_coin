#ifndef KYK_PROTOCOL_H__
#define KYK_PROTOCOL_H__

#include "kyk_message.h"
#include "kyk_socket.h"

int kyk_ptl_ping(const char* node,
		 const char* service,
		 ptl_resp_buf** new_resp_buf);


#endif
