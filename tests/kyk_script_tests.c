#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_data.h"
#include "kyk_tx.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_utils.h"
#include "kyk_ser.h"
#include "beej_pack.h"
#include "mu_unit.h"

#define SC_PUBK_MAX_LEN 1000
#define SC_MAX_LEN 2000

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

/* 通过 spentTxId 可以找到 address 对应的 pubkey, 这是下笔交易的 scriptSig 需要包含 pubkey 才能解锁 scriptPubKey */
/* https://blockexplorer.com/api/tx/7ffe434034e42b4ca3f48eeacac7c6640de563efb8eb484265cbae8f2e4550b4     */

char* test_build_p2pkh_sc_from_pubkey()
{
    uint8_t target_pbk_sc[] = {
	0x76, 0xa9, 0x14, 0x0b, 0x5b, 0x85, 0x54, 0x81,
	0x00, 0xb9, 0x81, 0x64, 0xf7, 0x74, 0x8f, 0x93,
	0x1b, 0x66, 0xeb, 0x1b, 0x1b, 0x0e, 0xc8, 0x88,
	0xac
    };

    /* this is a uncompressed pubkey, it contains 65 bytes */
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

char* test_kyk_run_script()
{
    unsigned char sc_pubk[SC_PUBK_MAX_LEN];
    char *addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    char *sc_sig_hex = "47304402207f9837b1e2a45e1e7f8054cb841af7e62fd40bf1a9becbebf38e9befe605905b02201fd0d11e48183c0b812f5fdecc36c0caf6fd1184d3ebd85192d711824c02f015014104c4ae8574bd6a8a89af1fad3a945b14f6745cc998f544ab193ffc568b33598f2191dd06dd37c3b971f6f8452e84d86bcb82c29d7fb8787723ca08216a24051af3";
    uint8_t *sc_sig;
    uint8_t sc[SC_MAX_LEN];
    size_t sc_pubk_len, sc_sig_len, sc_len;
    int verified = 0;

    /* https://blockexplorer.com/api/rawtx/1e4f607d33175aa3b0a854c7d494ee0eb0ac3f0fc0a759ad1ddf88efbe8cd37d */
    /* https://blockexplorer.com/api/tx/1e4f607d33175aa3b0a854c7d494ee0eb0ac3f0fc0a759ad1ddf88efbe8cd37d */
    /* unsig_tx -> 0200000001b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea010000001976a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88acfeffffff015cc10000000000001976a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac080b0700 */
    uint8_t unsig_tx[1000];
    uint8_t *utx_cpy = unsig_tx;
    uint32_t htype = HTYPE_SIGHASH_ALL;

    kyk_tx_inc_ser(&utx_cpy, "version-no", 2);
    
    kyk_tx_inc_ser(&utx_cpy, "in-counter", 1);

    kyk_tx_inc_ser(&utx_cpy, "pre-tx-hash:hex", "b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea");

    kyk_tx_inc_ser(&utx_cpy, "pre-txout-inx", 1);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-len", 0x19);
    
    kyk_tx_inc_ser(&utx_cpy, "txout-sc-pubkey:hex", "76a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88ac");

    kyk_tx_inc_ser(&utx_cpy, "seq-no", 0xfeffffff);

    kyk_tx_inc_ser(&utx_cpy, "out-counter", 1);

    kyk_tx_inc_ser(&utx_cpy, "txout-value", 49500);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-len", 0x19);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-pubkey:hex", "76a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac");

    kyk_tx_inc_ser(&utx_cpy, "lock-time", 461576);

    beej_pack(utx_cpy, "<L", htype);
    utx_cpy += sizeof(htype);


    /* 从 hex 字符串直接拷贝 scriptSig 到内存 */
    sc_sig = kyk_alloc_hex(sc_sig_hex, &sc_sig_len);

    /* 从比特币地址中提取 pay-to-pubkey-hash 脚本 */
    sc_pubk_len = p2pkh_sc_from_address(sc_pubk, addr);

    /* 合并 scriptSig 和 scriptPubKey 为一个脚本 */
    sc_len = kyk_combine_script(sc, sc_sig, sc_sig_len, sc_pubk, sc_pubk_len);

    verified = kyk_run_script(sc, sc_len, unsig_tx, utx_cpy - unsig_tx);    

    mu_assert(verified == 1, "Failed to test verify sc pubkey");

    free(sc_sig);

    return NULL;

}


char* test_kyk_build_p2pkh_sc_from_address()
{
    char* addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    uint8_t expect_sc[] = {
	0x76, 0xa9, 0x14, 0xc7, 0x3e, 0x88, 0xdf, 0xa4,
	0x5a, 0x94, 0x0b, 0xbe, 0xc4, 0xf5, 0x65, 0x4b,
	0x91, 0x02, 0x54, 0xe8, 0xb5, 0xd7, 0xbe, 0x88,
	0xac
    };

    unsigned char* sc = NULL;
    size_t sc_len = 0;
    int res = -1;

    res = kyk_build_p2pkh_sc_from_address(addr, strlen(addr), &sc, &sc_len);
    mu_assert(res == 0, "Failed to test_kyk_build_p2pkh_sc_from_address");
    mu_assert(kyk_digest_eq(sc, expect_sc, sc_len), "Failed to test_kyk_build_p2pkh_sc_from_address");

    free(sc);

    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_p2pkh_sc_from_address);
    mu_run_test(test_build_p2pkh_sc_from_pubkey);
    mu_run_test(test_kyk_run_script);
    mu_run_test(test_kyk_build_p2pkh_sc_from_address);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
