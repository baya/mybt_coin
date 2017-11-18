#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "kyk_script.h"
#include "mu_unit.h"

char* test_p2pkh_sc_from_address()
{
    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_p2pkh_sc_from_address);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
