#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_config.h"
#include "mu_unit.h"

char* test_kyk_config_create()
{
    struct config* cfg = kyk_config_create();
    mu_assert(cfg != NULL, "Failed to test creating config");
    mu_assert(cfg -> fileName == 0, "Failed to test creating config");
    mu_assert(cfg -> list == 0, "Failed to test creating config");

    return NULL;
}

char* test_kyk_config_load()
{
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_config_create);
    mu_run_test(test_kyk_config_load);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

