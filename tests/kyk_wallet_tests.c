#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_wallet.h"
#include "mu_unit.h"

char* test_kyk_create_wallet_key()
{
    struct kyk_wallet_key* wkey = NULL;
    uint32_t cfg_idx = 0;
    const char* desc = "main key";
    char* errmsg = "failed to test kyk_create_wallet_key";
    
    wkey = kyk_create_wallet_key(cfg_idx, desc);
    check(wkey, "failed to kyk_create_wallet_key");
    mu_assert(wkey -> cfg_idx == cfg_idx, "failed to set the correct cfgidx");
    mu_assert(strcmp(wkey -> desc, desc) == 0, "failed to set the correct desc");
    // printf("btc address: %s\n", wkey -> btc_addr);
    
    return NULL;

error:
    return errmsg;
}

char* test_wallet_add_key()
{
    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    mu_run_test(test_kyk_create_wallet_key);
    mu_run_test(test_wallet_add_key);

    return NULL;
}

MU_RUN_TESTS(all_tests);
