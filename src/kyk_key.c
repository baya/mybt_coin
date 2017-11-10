#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

#include "kyk_key.h"
#include "dbg.h"


struct kyk_key {
    EC_KEY  *key;
    uint8_t *pub_key;
    size_t  pub_len;
};

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
