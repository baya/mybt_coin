#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_address.h"
#include "kyk_pem.h"
#include "dbg.h"

int get_priv_from_pem(uint8_t *priv, const char *pem_file_name)
{
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ec_key = NULL;
    const BIGNUM *priv_bn = NULL;

    FILE *fp = fopen(pem_file_name, "r");
    check(fp != NULL, "Failed to open Pem file");
    
    evp_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    check(evp_key != NULL, "Failed to read pem");

    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(priv_bn, priv);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    fclose(fp);

    return 1;
    
error:
    if(ec_key) EC_KEY_free(ec_key);
    if(evp_key) EVP_PKEY_free(evp_key);
    
    return -1;
}

char *make_address_from_pem(const char *pem_name)
{
    uint8_t priv[32];
    char *addr = NULL;

    int res = 0;
    res = get_priv_from_pem(priv, pem_name);
    check(res > 0, "failed to get private key from pem file");
    addr = kyk_make_address(priv, sizeof(priv));

    return addr;

error:
    if(addr) free(addr);
    return NULL;
}

