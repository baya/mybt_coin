#ifndef __KYK_SHA_H
#define __KYK_SHA_H

#include <openssl/sha.h>
#include <openssl/ripemd.h>

struct kyk_hash{
    size_t len;
    unsigned char *body;
};

unsigned char * kyk_sha256(const char *str, size_t len);
unsigned char * kyk_dble_sha256(const char *str, size_t len);
struct kyk_hash *kyk_inver_hash(const char *src, size_t len);
void kyk_dgst_rmd160(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_sha256(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_hash256(uint8_t *digest, const uint8_t *message, size_t len);
void kyk_dgst_hash160(uint8_t *digest, const uint8_t *message, size_t len);

#endif
