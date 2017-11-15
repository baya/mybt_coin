#ifndef __KYK_BASE58_H
#define __KYK_BASE58_H

#include <openssl/bn.h>

enum key_address {
    PUBKEY_ADDRESS       = 0,
    SCRIPT_ADDRESS       = 5,
    PRIVKEY_ADDRESS      = 128,
    PUBKEY_ADDRESS_TEST  = 111,
    SCRIPT_ADDRESS_TEST  = 196,
    PRIVKEY_ADDRESS_TEST = 239,
};

char *kyk_base58(const uint8_t *bytes, size_t len);
char *kyk_base58check(uint8_t addrtype, const uint8_t *bytes, size_t len);
int raw_decode_base58(BIGNUM *bn, const char *src, size_t len);
void base58_get_checksum(uint8_t csum[4], const uint8_t *buf, size_t buflen);
int validate_base58_checksum(const uint8_t *buf, size_t buflen);
int kyk_base58_decode_check(const char* src, size_t src_len, uint8_t** dst, size_t* dst_len);

#endif
