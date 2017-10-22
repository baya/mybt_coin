#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/pem.h>

#include "kyk_address.h"


int main()
{
    uint8_t priv[32];
    EVP_PKEY *evp_key;
    EC_KEY *ec_key;
    const BIGNUM *priv_bn;
    char *addr;

    FILE *fp = fopen("kyk-gens-priv.pem", "r");
    if(!fp){
	perror("Pem File opening failed");
        return EXIT_FAILURE;
    }
    evp_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!evp_key)	{
	fprintf(stderr, "Unable to read pem\n");
	return -1;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(priv_bn, priv);
    kyk_print_hex("private key ", priv, sizeof(priv));


    addr = kyk_make_address(priv);

    printf("address     : %s\n", addr);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    free(addr);
    fclose(fp);

    return 0;
}
