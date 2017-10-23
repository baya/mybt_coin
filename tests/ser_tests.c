#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "kyk_ser.h"
#include "kyk_utils.h"
#include "mu_unit.h"


char *test_tx_ser()
{
    uint8_t buf[1000];
    size_t buf_len = 0;
    uint8_t *buf_cpy = buf;

    kyk_tx_inc_ser(&buf_cpy, "version-no", 2);
    kyk_tx_inc_ser(&buf_cpy, "in-counter", 1);
    kyk_tx_inc_ser(&buf_cpy, "version-no", 2);
    kyk_tx_inc_ser(&buf_cpy, "in-counter", 1); 
    kyk_tx_inc_ser(&buf_cpy, "pre-tx-hash:hex", "b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea");
    kyk_tx_inc_ser(&buf_cpy, "pre-txout-inx", 1);
    kyk_tx_inc_ser(&buf_cpy, "txout-sc-len", 0x19);
    kyk_tx_inc_ser(&buf_cpy, "txout-sc-pubkey:hex", "76a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88ac");
    kyk_tx_inc_ser(&buf_cpy, "seq-no", 0xfeffffff);
    kyk_tx_inc_ser(&buf_cpy, "out-counter", 1);
    kyk_tx_inc_ser(&buf_cpy, "txout-value", 49500);
    kyk_tx_inc_ser(&buf_cpy, "txout-sc-len", 0x19);
    kyk_tx_inc_ser(&buf_cpy, "txout-sc-pubkey:hex", "76a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac");
    kyk_tx_inc_ser(&buf_cpy, "lock-time", 461576);
    buf_len = buf_cpy - buf;

    size_t target_tx_len = 0;
    uint8_t *target_tx_ser = kyk_alloc_hex("02000000010200000001b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea010000001976a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88acfeffffff015cc10000000000001976a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac080b0700", &target_tx_len);

    mu_assert(buf_len == target_tx_len, "Failed to serialize Tx");
    mu_assert(kyk_digest_eq(buf, target_tx_ser, buf_len), "Failed to serialize Tx");

    return NULL;
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_tx_ser);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
