#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "mu_unit.h"

char *test_ecdsa()
{

    uint8_t priv_bytes[32] = {
	0x18,0xE1,0x4A,0x7B,0x6A,0x30,0x7F,0x42,
	0x6A,0x94,0xF8,0x11,0x47,0x01,0xE7,0xC8,
	0xE7,0x74,0xE7,0xF9,0xA4,0x7E,0x2C,0x20,
	0x35,0xDB,0x29,0xA2,0x06,0x32,0x17,0x25
    };

    EC_KEY *key;
    uint8_t priv[32];
    uint8_t *pub = NULL;
    const BIGNUM *priv_bn;
    char *err_msg = "Failed to test ecdsa";

    point_conversion_form_t conv_forms[] = {
        POINT_CONVERSION_UNCOMPRESSED,
        POINT_CONVERSION_COMPRESSED
    };

    const char *conv_forms_desc[] = {
        "uncompressed",
        "compressed"
    };

    key = kyk_ec_new_keypair(priv_bytes);
    check(key != NULL, "Failed to create keypair");

    priv_bn = EC_KEY_get0_private_key(key);
    check(priv_bn != NULL, "Failed to decode private key");
    
    BN_bn2bin(priv_bn, priv);
    size_t i = 0;
    uint8_t target_pub1[65];
    kyk_parse_hex(target_pub1, "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6");
    uint8_t target_pub2[33];
    kyk_parse_hex(target_pub2, "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352");

    /* get encoded public key from EC_KEY in all conversion forms */
    for (i = 0; i < sizeof(conv_forms) / sizeof(point_conversion_form_t); ++i) {
        size_t pub_len;
        uint8_t *pub_copy;

        EC_KEY_set_conv_form(key, conv_forms[i]);

        pub_len = i2o_ECPublicKey(key, NULL);
        pub = calloc(pub_len, sizeof(uint8_t));

        /* pub_copy is needed because i2o_ECPublicKey alters the input pointer */
        pub_copy = pub;
	size_t res = i2o_ECPublicKey(key, &pub_copy);
	check(res == pub_len, "Failed to decode public key");

        printf("conversion form: %s\n", conv_forms_desc[i]);
	if(i == 0){
	    mu_assert(kyk_digest_eq(target_pub1, pub, pub_len), "failed to get the correct uncompressed pub");
	} else {
	    mu_assert(kyk_digest_eq(target_pub2, pub, pub_len), "failed to get the correct compressed pub");
	}
        //kyk_print_hex("pub      ", pub, pub_len);

        free(pub);
    }

    /* release keypair */

    EC_KEY_free(key);

    return NULL;
    
error:
    if(pub) free(pub);
    if(key) EC_KEY_free(key);
    return err_msg;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_ecdsa);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

