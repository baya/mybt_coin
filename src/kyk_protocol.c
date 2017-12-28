#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "kyk_protocol.h"
#include "kyk_utils.h"
#include "beej_pack.h"
#include "dbg.h"

/* The ping message is sent primarily to confirm that the TCP/IP connection is still valid. */
/* An error in transmission is presumed to be a closed connection and the address is removed as a current peer. */
int kyk_ptl_ping_req(const char* node,
		     const char* service,
		     ptl_message** rep_msg)
{
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    struct ptl_ping_entity* et = NULL;
    int res = -1;

    res = kyk_new_ping_entity(&et);
    check(res == 0, "Failed to kyk_ptl_ping: kyk_new_ping_entity failed");

    res = kyk_build_new_ping_payload(&pld, et);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_build_new_ptl_message(&msg, KYK_MSG_TYPE_PING, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_send_ptl_msg(node, service, msg, rep_msg);
    check(res == 0, "Failed to kyk_ptl_ping");

    return 0;

error:

    return -1;

}

/* The pong message is sent in response to a ping message. In modern protocol versions, a pong response is generated using a nonce included in the ping. */
int kyk_ptl_pong_rep(int sockfd, ptl_message* req_msg)
{
    ptl_payload* pld = NULL;
    ptl_payload* rep_pld = NULL;
    ptl_message* rep_msg = NULL;
    uint64_t nonce = 0;
    int res = -1;
    
    check(req_msg, "Failed to kyk_ptl_pong_rep: req_msg is NULL");

    pld = req_msg -> pld;
    
    check(pld, "Failed to kyk_ptl_pong_rep: pld is NULL");
    check(pld -> data, "Failed to kyk_ptl_pong_rep: pld -> data is NULL");
    
    beej_unpack(pld -> data, "<Q", &nonce);

    res = kyk_build_new_pong_payload(&rep_pld, nonce);
    check(res == 0, "Failed to kyk_ptl_pong_rep: kyk_build_new_pong_payload failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_PONG, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_pong_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_pong_rep");
    

    return 0;

error:

    return -1;
}

/* When a node creates an outgoing connection, it will immediately advertise its version. */
/* The remote node will respond with its version. No further communication is possible until both peers have exchanged their version. */
int kyk_ptl_version_req(const char* node,
			const char* service,
			ptl_message* req_msg,
			ptl_message** rep_msg)
{
}
