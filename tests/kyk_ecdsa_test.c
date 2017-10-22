#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "kyk_ecdsa.h"
#include "kyk_utils.h"

int main()
{
    uint8_t priv_bytes[32] = {
	0x18,0xE1,0x4A,0x7B,0x6A,0x30,0x7F,0x42,
	0x6A,0x94,0xF8,0x11,0x47,0x01,0xE7,0xC8,
	0xE7,0x74,0xE7,0xF9,0xA4,0x7E,0x2C,0x20,
	0x35,0xDB,0x29,0xA2,0x06,0x32,0x17,0x25
    };

    EC_KEY *key;
    uint8_t priv[32];
    uint8_t *pub;
    const BIGNUM *priv_bn;

    point_conversion_form_t conv_forms[] = {
        POINT_CONVERSION_UNCOMPRESSED,
        POINT_CONVERSION_COMPRESSED
    };

    const char *conv_forms_desc[] = {
        "uncompressed",
        "compressed"
    };

    key = kyk_ec_new_keypair(priv_bytes);
    if (!key) {
        puts("Unable to create keypair");
        return -1;
    }

    kyk_print_hex("privkey #1", priv_bytes, sizeof(priv));

    priv_bn = EC_KEY_get0_private_key(key);
    if (!priv_bn) {
        puts("Unable to decode private key");
        return -1;
    }
    BN_bn2bin(priv_bn, priv);
    kyk_print_hex("privkey #2", priv, sizeof(priv));

    /* get encoded public key from EC_KEY in all conversion forms */

    for (int i = 0; i < sizeof(conv_forms) / sizeof(point_conversion_form_t); ++i) {
        size_t pub_len;
        uint8_t *pub_copy;

        EC_KEY_set_conv_form(key, conv_forms[i]);

        pub_len = i2o_ECPublicKey(key, NULL);
        pub = calloc(pub_len, sizeof(uint8_t));

        /* pub_copy is needed because i2o_ECPublicKey alters the input pointer */
        pub_copy = pub;
        if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
            puts("Unable to decode public key");
            return -1;
        }

        printf("conversion form: %s\n", conv_forms_desc[i]);
        kyk_print_hex("pub      ", pub, pub_len);

        free(pub);
    }

    /* release keypair */

    EC_KEY_free(key);

    return 0;
}
