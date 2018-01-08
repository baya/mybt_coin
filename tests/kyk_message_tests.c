#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "test_data.h"
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

char* test_kyk_build_new_getheaders_entity()
{
    ptl_gethder_entity* et = NULL;
    uint32_t version = 1;
    int res = -1;

    res = kyk_build_new_getheaders_entity(&et, version);
    mu_assert(res == 0, "Failed test_kyk_build_new_getheaders_entity");
    mu_assert(et, "Failed to kyk_build_new_getheaders_entity");

    return NULL;
}

char* test_kyk_new_seri_gethder_entity_to_pld()
{
    ptl_gethder_entity* et = NULL;
    ptl_payload* pld = NULL;
    uint32_t version = 1;
    int res = -1;

    res = kyk_build_new_getheaders_entity(&et, version);
    check(res == 0, "Failed to test_kyk_new_seri_gethder_entity_to_pld: kyk_build_new_getheaders_entity failed");

    res = kyk_new_seri_gethder_entity_to_pld(et, &pld);
    mu_assert(res == 0, "Failed to test_kyk_new_seri_gethder_entity_to_pld");

    return NULL;

error:

    return "Failed to test_kyk_new_seri_gethder_entity_to_pld";

}

char* test_kyk_seri_hd_chain_to_new_pld()
{
    ptl_payload* pld = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    uint8_t buf[160] = {
	0x01, 0x00, 0x00, 0x00, 0x55, 0xbd, 0x84, 0x0a,
	0x78, 0x79, 0x8a, 0xd0, 0xda, 0x85, 0x3f, 0x68,
	0x97, 0x4f, 0x3d, 0x18, 0x3e, 0x2b, 0xd1, 0xdb,
	0x6a, 0x84, 0x2c, 0x1f, 0xee, 0xcf, 0x22, 0x2a,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x10, 0x4c, 0xcb,
	0x05, 0x42, 0x1a, 0xb9, 0x3e, 0x63, 0xf8, 0xc3,
	0xce, 0x5c, 0x2c, 0x2e, 0x9d, 0xbb, 0x37, 0xde,
	0x27, 0x64, 0xb3, 0xa3, 0x17, 0x5c, 0x81, 0x66,
	0x56, 0x2c, 0xac, 0x7d, 0x51, 0xb9, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x28, 0x3e, 0x9e, 0x70,
	0x01, 0x00, 0x00, 0x00, 0xee, 0xa2, 0xd4, 0x8d,
	0x2f, 0xce, 0xd4, 0x34, 0x68, 0x42, 0x83, 0x5c,
	0x65, 0x9e, 0x49, 0x3d, 0x32, 0x3f, 0x06, 0xd4,
	0x03, 0x44, 0x69, 0xa8, 0x90, 0x57, 0x14, 0xd1,
	0x00, 0x00, 0x00, 0x00, 0xf2, 0x93, 0xc8, 0x69,
	0x73, 0xe7, 0x58, 0xcc, 0xd1, 0x19, 0x75, 0xfa,
	0x46, 0x4d, 0x4c, 0x3e, 0x85, 0x00, 0x97, 0x9c,
	0x95, 0x42, 0x5c, 0x7b, 0xe6, 0xf0, 0xa6, 0x53,
	0x14, 0xd2, 0xf2, 0xd5, 0xc9, 0xba, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x07, 0xa8, 0xf2, 0x26,
    };
    int res = -1;
    
    res = kyk_deseri_blk_hd_chain(&hd_chain, buf, sizeof(buf));
    check(res == 0, "Failed to test_kyk_seri_hd_chain_to_new_pld: kyk_deseri_blk_hd_chain failed");
    res = kyk_seri_hd_chain_to_new_pld(&pld, hd_chain);
    mu_assert(res == 0, "Failed to test_kyk_seri_hd_chain_to_new_pld");

    return NULL;

error:

    return "Failed to test_kyk_seri_hd_chain_to_new_pld";
}

char* test_kyk_deseri_new_ptl_inv_list()
{
    uint8_t buf[] = {
	0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x6c, 0x9e, 0xf8, 0xc1, 0xf8, 0xb2, 0xa3, 0x01,
	0x2e, 0xc1, 0xbd, 0xea, 0x72, 0x96, 0xf9, 0x5a, 0xe2, 0x16, 0x81, 0x79, 0x9f, 0x8a, 0xdf, 0x96,
	0x7f, 0x54, 0x8b, 0xf8, 0xf3, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xf5, 0x65, 0xc3, 0xbd,
	0x00, 0xad, 0x4b, 0xc8, 0x10, 0x2b, 0x8d, 0x7b, 0x8d, 0x2b, 0x7b, 0xa3, 0xe3, 0x55, 0xcd, 0xcf,
	0xfc, 0x3e, 0xda, 0x79, 0x40, 0x93, 0xa3, 0x26, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
	0x46, 0xd6, 0x5d, 0x4a, 0xa1, 0x23, 0x5f, 0x11, 0x4b, 0xa4, 0xdc, 0x1b, 0x40, 0x27, 0x2e, 0xc6,
	0xbd, 0xba, 0x57, 0x47, 0x6d, 0x21, 0x0e, 0xa8, 0x46, 0xe9, 0x26, 0x92, 0x54, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x61, 0xc8, 0xca, 0x8e, 0x60, 0x6f, 0xee, 0x1f, 0x5f, 0xea, 0x8f, 0x00, 0x27,
	0x97, 0x56, 0x7c, 0xf9, 0x83, 0xc4, 0x27, 0xbd, 0x03, 0x66, 0x65, 0xfe, 0x15, 0xae, 0xf6, 0x4d,
	0x3a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x8b, 0x9c, 0x60, 0x81, 0x19, 0xf6, 0xbc, 0x5d,
	0x86, 0x31, 0x62, 0x99, 0x59, 0xaa, 0x65, 0x81, 0xfb, 0x75, 0x7c, 0xbf, 0xca, 0xf8, 0x07, 0xbd,
	0x37, 0x97, 0xc0, 0xdc, 0x5d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7a, 0xde, 0x07, 0xe7, 0xa1,
	0xa4, 0xdb, 0x59, 0x3a, 0x71, 0xdb, 0xb2, 0x18, 0xf4, 0x47, 0x8a, 0x18, 0x93, 0x83, 0x43, 0x41,
	0xad, 0x5b, 0x38, 0xec, 0xed, 0xa3, 0xce, 0x32
    };

    struct ptl_inv* inv_list = NULL;
    varint_t inv_count = 0;
    int res = -1;

    res = kyk_deseri_new_ptl_inv_list(buf, &inv_list, &inv_count);
    mu_assert(res == 0, "Failed to test_kyk_deseri_new_ptl_inv_list");

    /* kyk_print_inv_list(inv_list, inv_count); */
    
    return NULL;
}

char* test_kyk_seri_blk_to_new_pld()
{
    struct kyk_block* blk = NULL;
    ptl_payload* pld = NULL;
    size_t blk_size = 0;
    int res = -1;

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_size);
    check(res == 0, "Failed to test_kyk_seri_blk_to_new_pld: kyk_deseri_new_block failed");

    res = kyk_seri_blk_to_new_pld(&pld, blk);
    mu_assert(res == 0, "Failed to test_kyk_seri_blk_to_new_pld");
    
    return NULL;

error:

    return "Failed to test_kyk_seri_blk_to_new_pld";
}

char* test_kyk_build_new_reject_ptl_payload()
{
    ptl_payload* pld = NULL;
    var_str* msg = NULL;
    var_str* reason = NULL;
    int res = -1;

    msg = kyk_new_var_str("invalid block hash");
    reason = kyk_new_var_str("invalid block hash");
    res = kyk_build_new_reject_ptl_payload(&pld, msg, CC_REJECT_INVALID, reason, NULL, 0);
    mu_assert(res == 0, "Failed to test_kyk_build_new_reject_ptl_payload");
    
    return NULL;
}

char* test_kyk_deseri_new_reject_entity()
{
    ptl_reject_entity* et = NULL;
    uint8_t buf[] = {
	0x0e, 0x6e, 0x6f, 0x20, 0x66, 0x6f, 0x75, 0x6e,
	0x64, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x10,
	0x0e, 0x6e, 0x6f, 0x20, 0x66, 0x6f, 0x75, 0x6e,
	0x64, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b
    };
    int res = -1;

    res = kyk_deseri_new_reject_entity(buf, sizeof(buf), &et, NULL);
    mu_assert(res == 0, "Failed to test_kyk_deseri_new_reject_entity");

    /* kyk_print_ptl_reject_entity(et); */

    kyk_free_ptl_reject_entity(et);
    
    return NULL;
}

char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_kyk_build_btc_new_message_for_ping);
    mu_run_test(test_kyk_build_btc_new_message_for_pong);
    mu_run_test(test_kyk_build_new_ping_payload);
    mu_run_test(test_kyk_new_seri_ver_entity_to_pld);
    mu_run_test(test_kyk_build_new_getheaders_entity);
    mu_run_test(test_kyk_new_seri_gethder_entity_to_pld);
    mu_run_test(test_kyk_seri_hd_chain_to_new_pld);
    mu_run_test(test_kyk_deseri_new_ptl_inv_list);
    mu_run_test(test_kyk_seri_blk_to_new_pld);
    mu_run_test(test_kyk_build_new_reject_ptl_payload);
    mu_run_test(test_kyk_deseri_new_reject_entity);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
