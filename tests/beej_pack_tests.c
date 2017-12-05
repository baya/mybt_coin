#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "beej_pack.h"
#include "mu_unit.h"

char* test_beej_pack()
{
    return NULL;
}

char* test_beej_unpack()
{
    return NULL;
}


char *all_tests()
{
    mu_suite_start();
    mu_run_test(test_beej_pack);
    mu_run_test(test_beej_unpack);
    return NULL;
}

MU_RUN_TESTS(all_tests);
