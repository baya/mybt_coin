#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_utils.h"
#include "kyk_base58.h"
#include "mu_unit.h"

char* test_kyk_base58check()
{
    uint8_t priv[32] = {
	0x1e, 0x99, 0x42, 0x3a, 0x4e, 0xd2, 0x76, 0x08,
	0xa1, 0x5a, 0x26, 0x16, 0xa2, 0xb0, 0xe9, 0xe5,
	0x2c, 0xed, 0x33, 0x0a, 0xc5, 0x30, 0xed, 0xcc,
	0x32, 0xc8, 0xff, 0xc6, 0xa5, 0x26, 0xae, 0xdd	
    };

    uint8_t cpriv[33] = {
	0x1e, 0x99, 0x42, 0x3a, 0x4e, 0xd2, 0x76, 0x08,
	0xa1, 0x5a, 0x26, 0x16, 0xa2, 0xb0, 0xe9, 0xe5,
	0x2c, 0xed, 0x33, 0x0a, 0xc5, 0x30, 0xed, 0xcc,
	0x32, 0xc8, 0xff, 0xc6, 0xa5, 0x26, 0xae, 0xdd,
	0x01
    };

    char* res = NULL;
    
    /* WIF */
    char* wif_res = "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn";

    /* WIF-compressed */
    char* wifc_res = "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ";

    res = kyk_base58check(PRIVKEY_ADDRESS, priv, sizeof(priv));

    mu_assert(strcmp(res, wif_res) == 0, "Failed to get the correct base58check result");

    res = kyk_base58check(PRIVKEY_ADDRESS, cpriv, sizeof(cpriv));
    mu_assert(strcmp(res, wifc_res) == 0, "Failed to get the correct base58check result");

    return NULL;
}

char* test_kyk_base58_decode_check()
{
    uint8_t target_priv[32] = {
	0x1e, 0x99, 0x42, 0x3a, 0x4e, 0xd2, 0x76, 0x08,
	0xa1, 0x5a, 0x26, 0x16, 0xa2, 0xb0, 0xe9, 0xe5,
	0x2c, 0xed, 0x33, 0x0a, 0xc5, 0x30, 0xed, 0xcc,
	0x32, 0xc8, 0xff, 0xc6, 0xa5, 0x26, 0xae, 0xdd	
    };

    char* wif_src = "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn";
    uint8_t *priv;
    size_t priv_len = 0;
    int res = -1;

    res = kyk_base58_decode_check(wif_src, strlen(wif_src), &priv, &priv_len);
    mu_assert(res == 0, "failed to test kyk_base58_decode_check");
    mu_assert(priv_len == sizeof(target_priv), "failed to get the correct priv");
    mu_assert(kyk_digest_eq(priv, target_priv, priv_len), "failed to get the correct priv");

    free(priv);
    priv = NULL;

    /* WIF-compressed */
    char* wifc_src = "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ";
    
    /* By adding a sufix 0x01 to the target priv */
    uint8_t target_comp_priv[33] = {
	0x1e, 0x99, 0x42, 0x3a, 0x4e, 0xd2, 0x76, 0x08,
	0xa1, 0x5a, 0x26, 0x16, 0xa2, 0xb0, 0xe9, 0xe5,
	0x2c, 0xed, 0x33, 0x0a, 0xc5, 0x30, 0xed, 0xcc,
	0x32, 0xc8, 0xff, 0xc6, 0xa5, 0x26, 0xae, 0xdd,
	0x01
    };

    res = kyk_base58_decode_check(wifc_src, strlen(wifc_src), &priv, &priv_len);
    mu_assert(res == 0, "failed to test kyk_base58_decode_check");
    mu_assert(priv_len == sizeof(target_comp_priv), "failed to get the correct priv");
    mu_assert(kyk_digest_eq(priv, target_comp_priv, priv_len), "failed to get the correct priv");

    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_base58check);
    mu_run_test(test_kyk_base58_decode_check);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

