#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "kyk_utils.h"
#include "mu_unit.h"
#include "dbg.h"

char* test_get_suffix_digest()
{
    char* str = "ke10y99";
    int num = 0;
    int res = -1;
    errno = 0;

    res = kyk_get_suffix_digest(str, &num);
    mu_assert(res == 0, "failed to kyk_get_suffix_digest");
    mu_assert(num == 99, "failed to get the correct value");
    
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_get_suffix_digest);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

