#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "kyk_protocol.h"
#include "kyk_utils.h"
#include "beej_pack.h"
#include "kyk_block.h"
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
int kyk_ptl_version_rep(int sockfd, ptl_message* req_msg)
{
    ptl_ver_entity* ver_entity = NULL;
    ptl_message* rep_msg = NULL;
    ptl_ver_entity* ver = NULL;
    ptl_payload* pld = NULL;
    int32_t vers = 70014;
    const char* ip_src = LOCAL_IP_SRC;
    int port = 0;
    uint64_t nonce = 0;
    const char* agent = "/KykMiner:0.0.0.1/";
    int32_t start_height = 0;
    int res = -1;    
    
    port = 8333;
    
    check(req_msg, "Failed to kyk_ptl_version_rep: req_msg is NULL");

    res = kyk_deseri_new_version_entity(&ver_entity, req_msg -> pld -> data, NULL);
    check(res == 0, "Failed to kyk_ptl_version_rep");

    kyk_print_ptl_version_entity(ver_entity);

    res = kyk_build_new_version_entity(&ver, vers, ip_src, port, nonce, agent, strlen(agent), start_height);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_build_new_version_entity failed");

    res = kyk_new_seri_ver_entity_to_pld(ver, &pld);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_new_seri_ver_entity_to_pld failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_VERSION, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_reply_ptl_msg failed");
    
    return 0;

error:

    return -1;
}


int kyk_ptl_headers_rep(int sockfd,
			const ptl_message* req_msg,
			const struct kyk_blk_hd_chain* hd_chain)
{
    ptl_payload* pld = NULL;
    ptl_message* rep_msg = NULL;
    int res = -1;

    check(req_msg, "Failed to kyk_ptl_headers_rep: req_msg is NULL");
    check(hd_chain, "Failed to kyk_ptl_headers_rep: hd_chain is NULL");

    res = kyk_seri_hd_chain_to_new_pld(&pld, hd_chain);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_seri_hd_chain_to_new_pld failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_HEADERS, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_reply_ptl_msg failed");

    return 0;
    
error:

    return -1;
}


