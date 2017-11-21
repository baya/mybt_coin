#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "kyk_script.h"
#include "kyk_utils.h"
#include "mu_unit.h"

char* test_p2pkh_sc_from_address()
{
    char* addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    uint8_t target_pbk_sc[] = {
	0x76, 0xa9, 0x14, 0xc7, 0x3e, 0x88, 0xdf, 0xa4,
	0x5a, 0x94, 0x0b, 0xbe, 0xc4, 0xf5, 0x65, 0x4b,
	0x91, 0x02, 0x54, 0xe8, 0xb5, 0xd7, 0xbe, 0x88,
	0xac
    };
    uint8_t pbk_sc[MAX_SC_PUB_LEN];
    size_t pbk_sc_len = 0;

    pbk_sc_len = p2pkh_sc_from_address(pbk_sc, addr);
    mu_assert(pbk_sc_len == sizeof(target_pbk_sc), "failed to get the correct pbk sc len");
    mu_assert(kyk_digest_eq(pbk_sc, target_pbk_sc, pbk_sc_len), "failed to get the correct pbk sc content");
    
    return NULL;
}

/* 测试数据来源 */
/* https://blockexplorer.com/api/tx/1e4f607d33175aa3b0a854c7d494ee0eb0ac3f0fc0a759ad1ddf88efbe8cd37d */
/* scriptPubKey: { */
/* hex: "76a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac", */
/* asm: "OP_DUP OP_HASH160 0b5b85548100b98164f7748f931b66eb1b1b0ec8 OP_EQUALVERIFY OP_CHECKSIG", */
/* addresses: [ */
/* "1234567pqVWicibzaqhmWqNNSoxm7JB3mp" */
/* ], */
/* type: "pubkeyhash" */
/* } */
/* spentTxId: "7ffe434034e42b4ca3f48eeacac7c6640de563efb8eb484265cbae8f2e4550b4" */

/* 通过 spentTxId 可以找到 address 对应的 pubkey, 因为下笔交易的 scriptSig 需要包含 pubkey 才能解锁 scriptPubKey */
/* https://blockexplorer.com/api/tx/7ffe434034e42b4ca3f48eeacac7c6640de563efb8eb484265cbae8f2e4550b4     */

char* test_build_p2pkh_sc_from_pubkey()
{
    uint8_t target_pbk_sc[] = {
	0x76, 0xa9, 0x14, 0x0b, 0x5b, 0x85, 0x54, 0x81,
	0x00, 0xb9, 0x81, 0x64, 0xf7, 0x74, 0x8f, 0x93,
	0x1b, 0x66, 0xeb, 0x1b, 0x1b, 0x0e, 0xc8, 0x88,
	0xac
    };

    /* this is a uncompressed pubkey, it is contains 65 bytes */
    uint8_t pubkey[65] = {
	0x04, 0x12, 0x78, 0x82, 0x02, 0xff, 0x75, 0x15,
	0x00, 0xdd, 0xc2, 0x3b, 0x3b, 0x5a, 0x61, 0xea,
	0x30, 0xa8, 0x85, 0xc5, 0x4a, 0xb4, 0x2e, 0x01,
	0x7f, 0x8b, 0x1b, 0x24, 0xa9, 0x56, 0xef, 0xd5,
	0x3f, 0x88, 0x43, 0x1e, 0x72, 0x60, 0x5d, 0xa0,
	0x17, 0x31, 0x7d, 0x65, 0xf7, 0x29, 0x4d, 0xdc,
	0x05, 0xce, 0xfe, 0x27, 0xb3, 0xb2, 0x9e, 0x8f,
	0xe6, 0x88, 0xda, 0x1a, 0x9d, 0x93, 0xa7, 0x5e,
	0x33
    };

    struct kyk_buff* sc;
    int res = -1;

    res = build_p2pkh_sc_from_pubkey(pubkey, sizeof(pubkey), &sc);
    mu_assert(res == 0, "Failed to build_p2pkh_sc_from_pubkey");
    mu_assert(kyk_digest_eq(sc -> base, target_pbk_sc, sc -> len), "Failed to build_p2pkh_sc_from_pubkey");

    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_p2pkh_sc_from_address);
    mu_run_test(test_build_p2pkh_sc_from_pubkey);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
