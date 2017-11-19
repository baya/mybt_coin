#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/pem.h>

#include "kyk_utils.h"
#include "kyk_address.h"
#include "mu_unit.h"


char *test_make_address()
{
    uint8_t priv[32];
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ec_key = NULL;
    const BIGNUM *priv_bn;
    char *addr = NULL;
    char *target_addr = "1Te2roqFCPbG59tTP4fLjCZpEAiiwXAQm";
    char *err_msg = "Failed to test making address";

    FILE *fp = fopen("data/kyk-gens-priv.pem", "r");
    check(fp != NULL, "Pem File opening failed");
    evp_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    check(fp != NULL, "Unable to read pem");

    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(priv_bn, priv);
    addr = kyk_make_address(priv);

    mu_assert(strcmp(addr, target_addr) == 0, "failed to get the correct address 1Te2roqFCPbG59tTP4fLjCZpEAiiwXAQm");

    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    
    free(addr);
    fclose(fp);

    return NULL;
error:
    if(ec_key) EC_KEY_free(ec_key);
    if(evp_key) EVP_PKEY_free(evp_key);
    if(addr) free(addr);
    if(fp) fclose(fp);
    
    return err_msg;
}

char* test_make_address_from_pubkey()
{
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_address);
    mu_run_test(test_make_address_from_pubkey);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
