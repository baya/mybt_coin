#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "kyk_utils.h"
#include "kyk_script.h"
#include "mu_unit.h"

#define KYK_SC_MAX_LEN 1000

char *test_get_sc_pubkey_from_address()
{
    unsigned char sc[KYK_SC_MAX_LEN];
    char *addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    size_t len;

    /* 从比特币地址中提取 pay-to-pubkey-hash 脚本 */
    len = p2pkh_sc_from_address(sc, addr);
    size_t target_sc_len;
    uint8_t *target_sc = kyk_alloc_hex("76a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88ac", &target_sc_len);

    mu_assert(len = target_sc_len, "failed to get the correct pay-to-pubkey-hash len");
    mu_assert(kyk_digest_eq(target_sc, sc, len), "failed to get the correct pay-to-pubkey-hash");

    free(target_sc);

    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_get_sc_pubkey_from_address);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
