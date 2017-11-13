#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_wallet.h"
#include "mu_unit.h"

char* test_wallet_add_key()
{
    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    mu_run_test(test_wallet_add_key);

    return NULL;
}

MU_RUN_TESTS(all_tests);
