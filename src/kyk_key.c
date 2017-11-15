#include "kyk_key.h"
#include "dbg.h"

static int kyk_key_get_pubkey(struct kyk_key *k,
			      uint8_t     **pub,
			      size_t    *len);

struct kyk_key* kyk_key_generate_new(void)
{
    struct kyk_key* k;
    int s = 0;

    k = kyk_key_alloc();
    check(k != NULL, "failed to alloc kyk_key");

    s = EC_KEY_generate_key(k->key);
    check(s > 0, "EC_KEY_generate_key failed");

    s = EC_KEY_check_key(k->key);
    check(s > 0, "EC_KEY_check_key failed");

    EC_KEY_set_conv_form(k->key, POINT_CONVERSION_COMPRESSED);

    check(k -> pub_key == NULL, "invalid pub_key");
    check(k -> pub_len == 0, "invalid pub len");

    s = kyk_key_get_pubkey(k, &k->pub_key, &k->pub_len);
    check(s > 0, "failed to get pubkey");

    return k;

error:
    free_kyk_key(k);
    return NULL;
    
}


static int kyk_key_get_pubkey(struct kyk_key *k,
			      uint8_t     **pub,
			      size_t    *len)
{
    uint8_t *data;
    int res = 0;

    check(pub != NULL, "pub is null address");
    *pub = NULL;
    *len = 0;

    res = EC_KEY_check_key(k->key);
    check(res > 0, "EC_KEY_check_key failed");

    *len = i2o_ECPublicKey(k->key, 0);
    check(*len <= 65, "pub len should be <= 65");
    
    data = malloc(*len);
    check(data != NULL, "failed to malloc data");
    
    *pub = data;
    i2o_ECPublicKey(k->key, &data);

    return 1;

error:
    return 0;
}

struct kyk_key* kyk_key_alloc(void)
{
   struct kyk_key* k;

   k = malloc(sizeof *k);
   check(k != NULL, "failed to malloc kyk_key");
   
   k->key = EC_KEY_new_by_curve_name(NID_secp256k1);
   k->pub_key = NULL;
   k->pub_len = 0;

   return k;

error:
   return NULL;
}

void free_kyk_key(struct kyk_key* k)
{
    if(k == NULL){
	return;
    }

    free(k -> pub_key);
}


int kyk_key_get_privkey(struct kyk_key* k,
			uint8_t**   priv,
			size_t*     len)
{
    check(priv, "priv can not be blank");
    *priv = NULL;
    *len = 0;

    check(EC_KEY_check_key(k -> key), "invalid key");

    const BIGNUM *bn = EC_KEY_get0_private_key(k -> key);
    check(bn != NULL, "invalid bn");
    
    *len = BN_num_bytes(bn);
    *priv = malloc(*len);
    check(*priv != NULL, "failed to malloc");
    
    BN_bn2bin(bn, *priv);

    return 0;

error:
    return -1;
}

int kyk_key_cpy_pubkey(struct kyk_key *k,
		       uint8_t     **pub,
		       size_t    *len)
{
    check(pub, "pub can not be NULL");
    
    *pub = malloc(k->pub_len);
    check(*pub, "failed to malloc");
    
    *len = k -> pub_len;

    memcpy(*pub, k -> pub_key, *len);

    return 0;

error:
    return -1;
}

