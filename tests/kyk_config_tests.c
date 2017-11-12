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
    char* filename = "data/contacts.cfg";
    struct config* cfg;
    int res = -1;
    char *v = NULL;

    /*  contact0.addr = 1PBP4S44b1ro3kD6LQhBYnsF3fAp1HYPf2                          */
    /* 	contact0.label = Support bitc development -- https://bit-c.github.com       */
    /*  contact1.addr = 1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN                          */
    /* 	contact1.label = Free Software Foundation -- https://fsf.org/donate/        */
    /*  contact2.addr = 1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW                          */
    /* 	contact2.label = Bitcoin Foundation -- https://bitcoinfoundation.org/donate */
    /*  contacts.numEntries = 3                                                     */
    res = kyk_config_load(filename, &cfg);
    mu_assert(res == 0, "return value of config load should be 0");
    mu_assert(strcmp(cfg -> fileName, filename) == 0, "failed to get the correct config file name");
    //kyk_print_config(cfg);

    v = kyk_config_getstring(cfg, NULL, "contact0.addr");
    mu_assert(strcmp(v, "1PBP4S44b1ro3kD6LQhBYnsF3fAp1HYPf2") == 0, "Failed to get value of contact0.addr");
    
    v = kyk_config_getstring(cfg, NULL, "contact0.label");
    mu_assert(strcmp(v, "Support bitc development -- https://bit-c.github.com") == 0, "Failed to get value of contact0.label");

    v = kyk_config_getstring(cfg, NULL, "contact1.addr");
    mu_assert(strcmp(v, "1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN") == 0, "Failed to get value of contact1.addr");
    v = kyk_config_getstring(cfg, NULL, "contact1.label");
    mu_assert(strcmp(v, "Free Software Foundation -- https://fsf.org/donate/") == 0, "Failed to get value of contact1.label");

    v = kyk_config_getstring(cfg, NULL, "contact2.addr");
    mu_assert(strcmp(v, "1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW") == 0, "Failed to get value of contact1.addr");
    v = kyk_config_getstring(cfg, NULL, "contact2.label");
    mu_assert(strcmp(v, "Bitcoin Foundation -- https://bitcoinfoundation.org/donate") == 0, "Failed to get value of contact2.label");

    v = kyk_config_getstring(cfg, NULL, "contacts.numEntries");
    mu_assert(strcmp(v, "3") == 0, "Failed to get value of contacts.numEntries");

    
    
    kyk_config_free(cfg);
    
    return NULL;
}

char* test_kyk_config_write()
{

    struct config* cfg = kyk_config_create();
    char* filename = "data/config_write_test_tmp.cfg";
    char* str = "bar";
    int res = 0;

    kyk_config_setstring(cfg, str, "key%d", 0);
    res = kyk_config_write(cfg, filename);

    mu_assert(res == 0, "Failed to write config");

    return NULL;
}

char* test_kyk_config_setstring()
{
    struct config* cfg = kyk_config_create();
    char* str = "bar";
    char* key = "key0";
    char *v = NULL;

    kyk_config_setstring(cfg, str, "key%d", 0);
    v = kyk_config_getstring(cfg, NULL, key);

    mu_assert(strcmp(v, str) == 0, "Failed to get value of key0");
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_config_create);
    mu_run_test(test_kyk_config_load);
    mu_run_test(test_kyk_config_write);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

