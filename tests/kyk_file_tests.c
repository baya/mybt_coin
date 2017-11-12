#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_file.h"
#include "mu_unit.h"

char* test_kyk_file_exists()
{
    bool res;
    res = kyk_file_exists("no-exist-file.txt");
    mu_assert(!res, "file shoud be no exist");
    
    res = kyk_file_exists("data/i_am_here.txt");
    mu_assert(res, "file shoud be exist");
    return NULL;
}

char* test_kyk_file_create()
{
    int res = 0;
    res = kyk_file_create("/tmp/just_tmp.txt");
    mu_assert(res == 0, "failed to create file");
    
    return NULL;
}

char* test_kyk_file_mkdir()
{
    int res = 0;
    res = kyk_file_mkdir("/tmp/just_tmp_test_dir");
    mu_assert(res == 0, "failed to create directory");

    return NULL;
}

char* test_kyk_file_chmod()
{
    int res = 0;
    res = kyk_file_chmod("data/i_am_here.txt", 0700);
    mu_assert(res == 0, "failed to kyk_file_chmod");

    return NULL;
}


char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_kyk_file_exists);
    mu_run_test(test_kyk_file_create);
    /* mu_run_test(test_kyk_file_mkdir); */
    mu_run_test(test_kyk_file_chmod);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
