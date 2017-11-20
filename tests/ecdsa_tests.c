#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "kyk_sha.h"
#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "kyk_buff.h"
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

char* test_kyk_ec_sign()
{
    uint8_t priv_bytes[32] = {
        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };
    
    const char message[] = "Hello Bitcoin";
    char* errmsg = "Failed to test_kyk_ec_sign";

    uint8_t digest[32];
    struct kyk_buff* der = NULL;
    int res = -1;
    
    kyk_dgst_sha256(digest, (uint8_t *)message, strlen(message));

    res = kyk_ec_sign(priv_bytes, digest, sizeof(digest), &der);
    check(res == 0, "failed to kyk_ec_sign");

    free_kyk_buff(der);

    return NULL;

error:

    return errmsg;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_ecdsa);
    mu_run_test(test_kyk_ec_sign);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

