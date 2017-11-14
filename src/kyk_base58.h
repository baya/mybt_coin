#ifndef __KYK_BASE58_H
#define __KYK_BASE58_H

#include <openssl/bn.h>

char *kyk_base58(const uint8_t *bytes, size_t len);
char *kyk_base58check(const uint8_t *bytes, size_t len);
int raw_decode_base58(BIGNUM *bn, const char *src, size_t len);
void base58_get_checksum(uint8_t csum[4], const uint8_t *buf, size_t buflen);
int validate_base58_checksum(const uint8_t *buf, size_t buflen);
int kyk_decode_b58_priv(const char* src, size_t src_len, uint8_t** dst, size_t* dst_len);

#endif
