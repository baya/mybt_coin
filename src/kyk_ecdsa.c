#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_sha.h"
#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "kyk_buff.h"
#include "dbg.h"

int kyk_ec_sign(uint8_t* priv,
		const uint8_t* src,
		size_t src_len,
		struct kyk_buff** der
    )
{
    EC_KEY *key = NULL;
    ECDSA_SIG *signature = NULL;
    struct kyk_buff* der_cpy = NULL;
    size_t der_len = 0;
    uint8_t* bp = NULL;

    check(der, "failed to kyk_ec_sign: der can not be NULL");

    der_cpy = malloc(sizeof(struct kyk_buff));
    check(der_cpy, "failed to kyk_ec_sign: malloc error");
	
    key = kyk_ec_new_keypair(priv);
    check(key, "failed to kyk_ec_sign: unable to create keypair");

    signature = ECDSA_do_sign(src, src_len, key);
    check(signature, "failed to kyk_ec_sign: ECDSA_do_sign failed");
    
    der_len = ECDSA_size(key);
    der_cpy -> base = calloc(der_len, sizeof(uint8_t));
    check(der_cpy -> base, "failed to kyk_ec_sign: calloc error");
    
    der_cpy -> len = der_len;
    bp = der_cpy -> base;

    i2d_ECDSA_SIG(signature, &bp);

    *der = der_cpy;

    ECDSA_SIG_free(signature);
    EC_KEY_free(key);    

    return 0;

error:

    if(signature) ECDSA_SIG_free(signature);
    if(key) EC_KEY_free(key);    

    return -1;

}


EC_KEY *kyk_ec_new_keypair(const uint8_t *priv_bytes)
{
    EC_KEY *key;
    BIGNUM *priv;
    BN_CTX *ctx;
    const EC_GROUP *group;
    EC_POINT *pub;

    /* init empty OpenSSL EC keypair */

    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    /* set private key through BIGNUM */

    priv = BN_new();
    BN_bin2bn(priv_bytes, 32, priv);
    EC_KEY_set_private_key(key, priv);

    /* derive public key from private key and group */
    
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);

    /* release resources */

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);

    return key;
}

EC_KEY *kyk_ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len)
{
    EC_KEY *key;
    const uint8_t *pub_bytes_copy;

    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    pub_bytes_copy = pub_bytes;
    o2i_ECPublicKey(&key, &pub_bytes_copy, pub_len);

    return key;
}

int kyk_ec_sig_verify(uint8_t *buf, size_t buf_len,
		       uint8_t *der_sig, size_t der_sig_len,
		       uint8_t *pubkey, size_t pub_len)
{
    EC_KEY *key;
    ECDSA_SIG *signature;
    uint8_t digest[32];
    uint8_t suffix_pub[33];
    const uint8_t *der_sig_copy;

    int verified = 0;

    memcpy(suffix_pub, pubkey, sizeof(suffix_pub));
    key = kyk_ec_new_pubkey(pubkey, pub_len);
    if (!key) {
	fprintf(stderr, "Unable to create pubkey");
	return -1;
    }

    der_sig_copy = der_sig;
    signature = d2i_ECDSA_SIG(NULL, &der_sig_copy, der_sig_len);

    kyk_dgst_hash256(digest, buf, buf_len);
    verified = ECDSA_do_verify(digest, sizeof(digest), signature, key);

    ECDSA_SIG_free(signature);
    EC_KEY_free(key);
    
    return verified;
}
