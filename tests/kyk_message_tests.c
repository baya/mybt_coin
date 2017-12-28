#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "kyk_utils.h"
#include "kyk_message.h"
#include "mu_unit.h"
#include "dbg.h"

char* test_kyk_build_btc_new_message_for_ping()
{
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    struct ptl_ping_entity* et = NULL;
    int res = -1;

    kyk_new_ping_entity(&et);
    res = kyk_build_new_ping_payload(&pld, et);
    check(res == 0, "Failed to test_kyk_build_btc_new_message_for_ping: kyk_new_ptl_payload failed");

    res = kyk_build_new_ptl_message(&msg, KYK_MSG_TYPE_PING, NT_MAGIC_MAIN, pld);
    mu_assert(res == 0, "Failed to test_kyk_build_btc_new_message_for_ping");

    /* kyk_print_ptl_message(msg); */

    return NULL;

error:

    return "Failed to test_kyk_build_btc_new_message_for_ping";
}


char* test_kyk_build_btc_new_message_for_pong()
{
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    uint64_t nonce = 123;
    int res = -1;

    res = kyk_build_new_pong_payload(&pld, nonce);
    check(res == 0, "Failed to test_kyk_build_btc_new_message_for_ping: kyk_new_ptl_payload failed");

    res = kyk_build_new_ptl_message(&msg, KYK_MSG_TYPE_PONG, NT_MAGIC_MAIN, pld);
    mu_assert(res == 0, "Failed to test_kyk_build_btc_new_message_for_pong");

    /* kyk_print_ptl_message(msg); */
    
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

char* test_kyk_new_seri_ver_entity_to_pld()
{
    ptl_payload* pld = NULL;
    ptl_ver_entity* ver = NULL;
    int32_t vers = 70014;
    const char* ip_src = LOCAL_IP_SRC;
    int port = 8333;
    uint64_t nonce = 0;
    const char* agent = "/BobWallet:0.0.0.1/";
    int32_t start_height = 0;
    int res = -1;

    res = kyk_build_new_version_entity(&ver, vers, ip_src, port, nonce, agent, strlen(agent), start_height);
    check(res == 0, "Failed to test_kyk_new_seri_ver_entity_to_pld: kyk_build_new_version_entity failed");

    res = kyk_new_seri_ver_entity_to_pld(ver, &pld);
    mu_assert(res == 0, "Failed to test_kyk_new_seri_ver_entity_to_pld");

    return NULL;

error:

    return "Failed to test_kyk_new_seri_ver_entity_to_pld";

}

char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_kyk_build_btc_new_message_for_ping);
    mu_run_test(test_kyk_build_btc_new_message_for_pong);
    mu_run_test(test_kyk_build_new_ping_payload);
    mu_run_test(test_kyk_new_seri_ver_entity_to_pld);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
