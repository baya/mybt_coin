#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "kyk_utils.h"
#include "btc_message.h"
#include "mu_unit.h"
#include "dbg.h"

char* test_kyk_build_btc_new_message_for_ping()
{
    ptl_payload* pld = NULL;
    ptl_msg* msg = NULL;
    int res = -1;

    res = kyk_new_ptl_payload(&pld);
    check(res == 0, "Failed to test_kyk_build_btc_new_message_for_ping: kyk_new_ptl_payload failed");

    res = kyk_build_btc_new_message(&msg, KYK_MSG_TYPE_PING, NT_MAGIC_MAIN, pld);
    mu_assert(res == 0, "Failed to test_kyk_build_btc_new_message_for_ping");
    
    return NULL;

error:

    return "Failed to test_kyk_build_btc_new_message_for_ping";
}

char* test_kyk_build_new_ping_payload()
{
    ptl_payload* pld = NULL;
    struct ptl_ping_entity* et = NULL;     
    int res = -1;

    kyk_new_ping_entity(&et);
    res = kyk_build_new_ping_payload(&pld, et);
    mu_assert(res == 0, "Failed to test_kyk_build_new_ping_payload");
    mu_assert(pld -> len == 8, "Failed to test_kyk_build_new_ping_payload");
    /* printf("got nonce: %llu\n", et -> nonce); */

    kyk_free_ptl_payload(pld);
    free(et);
    
    return NULL;
}

char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_kyk_build_btc_new_message_for_ping);
    mu_run_test(test_kyk_build_new_ping_payload);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
