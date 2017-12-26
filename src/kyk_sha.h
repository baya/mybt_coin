#ifndef __KYK_SHA_H
#define __KYK_SHA_H

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "kyk_defs.h"

struct kyk_digst{
    size_t len;
    unsigned char *body;
};

unsigned char * kyk_sha256(const char *str, size_t len);
unsigned char * kyk_dble_sha256(const char *str, size_t len);
struct kyk_digst *kyk_inver_hash(const char *src, size_t len);
void kyk_dgst_rmd160(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_sha256(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_hash256(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_hash160(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_free_digst(struct kyk_digst *dg);
void kyk_dgst_hash_rmd160(uint8_t* digest, const uint8_t* message, size_t len);
int kyk_hash256(uint256* digest, const uint8_t* buf, size_t len);

#endif
