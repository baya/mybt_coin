#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "kyk_protocol.h"
#include "kyk_utils.h"
#include "dbg.h"

/* The pong message is sent in response to a ping message. In modern protocol versions, a pong response is generated using a nonce included in the ping. */
int kyk_ptl_ping(const char* node,
		 const char* service,
		 ptl_resp_buf** new_resp_buf)
{
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    ptl_resp_buf* resp_buf = NULL;
    struct ptl_ping_entity* et = NULL;
    int res = -1;

    res = kyk_new_ping_entity(&et);
    check(res == 0, "Failed to kyk_ptl_ping: kyk_new_ping_entity failed");

    res = kyk_build_new_ping_payload(&pld, et);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_build_btc_new_message(&msg, KYK_MSG_TYPE_PING, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_send_ptl_msg(node, service, msg, &resp_buf);
    check(res == 0, "Failed to kyk_ptl_ping");

    *new_resp_buf = resp_buf;

    return 0;

error:

    return -1;

}
