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
    uint8_t pubkey[] = {
	0x04, 0xc4, 0xae, 0x85, 0x74, 0xbd, 0x6a, 0x8a,
	0x89, 0xaf, 0x1f, 0xad, 0x3a, 0x94, 0x5b, 0x14,
	0xf6, 0x74, 0x5c, 0xc9, 0x98, 0xf5, 0x44, 0xab,
	0x19, 0x3f, 0xfc, 0x56, 0x8b, 0x33, 0x59, 0x8f,
	0x21, 0x91, 0xdd, 0x06, 0xdd, 0x37, 0xc3, 0xb9,
	0x71, 0xf6, 0xf8, 0x45, 0x2e, 0x84, 0xd8, 0x6b,
	0xcb, 0x82, 0xc2, 0x9d, 0x7f, 0xb8, 0x78, 0x77,
	0x23, 0xca, 0x08, 0x21, 0x6a, 0x24, 0x05, 0x1a,
	0xf3	
    };

    char* target_addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    char* addr = NULL;

    addr = kyk_make_address_from_pubkey(pubkey, sizeof(pubkey));
    mu_assert(strcmp(addr, target_addr) == 0, "failed to get the correct address");
    
    return NULL;
}

char* test2_make_address_from_pubkey()
{
    uint8_t pubkey[] = {
	0x03, 0xef, 0x50, 0x92, 0x20, 0x0f, 0x49, 0xae,
	0x02, 0x6c, 0xf6, 0xe5, 0xa8, 0x5d, 0x49, 0xcb,
	0x19, 0x4b, 0x9f, 0x89, 0x44, 0x48, 0xe9, 0x4f,
	0x7e, 0x75, 0x22, 0xeb, 0x9e, 0xfa, 0x72, 0xbe,
	0xe3
    };

    char* target_addr = "12f7cbrBn9Xupes1yrFevuMkRM7bXoey6d";
    char* addr = NULL;

    addr = kyk_make_address_from_pubkey(pubkey, sizeof(pubkey));
    mu_assert(strcmp(addr, target_addr) == 0, "failed to get the correct address");
    
    return NULL;
}

char* test3_make_address_from_pubkey()
{
    uint8_t pubkey[] = {
	0x02, 0xd9, 0x7b, 0x41, 0x2a, 0x3d, 0x69, 0x0f,
	0xc6, 0x89, 0xa7, 0x8d, 0x43, 0xac, 0xbc, 0x37,
	0x84, 0xa6, 0x57, 0xf0, 0x45, 0xf4, 0x40, 0x5c,
	0x8f, 0xa7, 0x4d, 0x2f, 0x41, 0x96, 0x8e, 0xb9,
	0x48	
    };

    char* target_addr = "12ZYkesYJNdHmg3DPxx64LhYWq8Ddmx3HW";
    char* addr = NULL;

    addr = kyk_make_address_from_pubkey(pubkey, sizeof(pubkey));
    mu_assert(strcmp(addr, target_addr) == 0, "failed to get the correct address");
    
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_address);
    mu_run_test(test_make_address_from_pubkey);
    mu_run_test(test2_make_address_from_pubkey);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
