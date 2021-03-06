#ifndef __KYK_KEY_H__
#define __KYK_KEY_H__

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

#include "kyk_defs.h"

struct kyk_key {
    EC_KEY*  key;
    uint8_t* pub_key;
    size_t   pub_len;
};

struct kyk_key* kyk_key_alloc(void);
void free_kyk_key(struct kyk_key* k);
struct kyk_key* kyk_key_generate_new(void);
int kyk_key_get_privkey(struct kyk_key* k,
			uint8_t**   priv,
			size_t*     len);
int kyk_key_cpy_pubkey(struct kyk_key *k,
		       uint8_t     **pub,
		       size_t    *len);


#endif
