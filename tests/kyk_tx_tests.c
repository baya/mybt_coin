#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "mu_unit.h"

char* test_seri_tx()
{
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_seri_tx);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
