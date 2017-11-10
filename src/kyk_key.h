#ifndef __KYK_KEY_H__
#define __KYK_KEY_H__

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

struct kyk_key {
    EC_KEY  *key;
    uint8_t *pub_key;
    size_t  pub_len;
};


struct kyk_key* kyk_key_alloc(void);
void free_kyk_key(struct kyk_key* k);
struct kyk_key* kyk_key_generate_new(void);

#endif
