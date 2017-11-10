#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_key.h"
#include "kyk_utils.h"
#include "mu_unit.h"

char* test_generate_new_key()
{
    struct kyk_key* k;
    char* errmsg = "failed to test generate new key";
    errno = 0;

    k = kyk_key_generate_new();
    check(k != NULL, "failed to generate new key");

    return NULL;

error:
    free_kyk_key(k);
    return errmsg;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_generate_new_key);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

