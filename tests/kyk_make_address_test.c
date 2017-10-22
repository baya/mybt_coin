#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/pem.h>

#include "kyk_address.h"


int main()
{
    uint8_t _h_priv_bytes[32] = {
	0x18,0xE1,0x4A,0x7B,0x6A,0x30,0x7F,0x42,
	0x6A,0x94,0xF8,0x11,0x47,0x01,0xE7,0xC8,
	0xE7,0x74,0xE7,0xF9,0xA4,0x7E,0x2C,0x20,
	0x35,0xDB,0x29,0xA2,0x06,0x32,0x17,0x25
    };

    uint8_t _h1_priv_bytes[32] = {
	0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
	0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
	0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
	0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };

    uint8_t *priv_bytes;
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
    kyk_print_hex("", priv, sizeof(priv));
    // EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_UNCOMPRESSED);
    

    //priv_bytes = data[0];

    //addr = kyk_make_address(priv_bytes);

    //printf("%s\n", addr);

    //free(addr);

    fclose(fp);

    return 0;
}
