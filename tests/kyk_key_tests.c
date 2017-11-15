#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_key.h"
#include "kyk_utils.h"
#include "mu_unit.h"
#include "kyk_address.h"

#define PRIVATE_KEY_LEN 32

char* test_generate_new_key()
{
    struct kyk_key* k;
    char *addr = NULL;
    char* errmsg = "failed to test generate new key";
    errno = 0;

    k = kyk_key_generate_new();
    check(k != NULL, "failed to generate new key");

    addr = kyk_make_address_from_pub(k -> pub_key, k -> pub_len);
    printf("addr: %s\n", addr);
    check(addr != NULL, "failed to make address");

    return NULL;

error:
    free_kyk_key(k);
    return errmsg;
}

char* test_kyk_key_get_privkey()
{
    struct kyk_key* k = NULL;
    uint8_t* priv = NULL;
    size_t len = 0;
    int res = -1;

    k = kyk_key_generate_new();
    res = kyk_key_get_privkey(k, &priv, &len);
    mu_assert(res == 0, "Failed to test kyk_key_get_privkey");
    mu_assert(len == PRIVATE_KEY_LEN, "Failed to get the correct private key len");
    mu_assert(priv != NULL, "Failed to get the correct private key");

    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_generate_new_key);
    mu_run_test(test_kyk_key_get_privkey);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

