#ifndef KYK_BITCOIN_VARINT_H
#define KYK_BITCOIN_VARINT_H

#include "kyk_defs.h"

#define varint_t uint64_t

typedef struct var_str {
    varint_t len;
    char* data;
} var_str;

/* Returns bytes used (up to 9) */
size_t kyk_pack_varint(unsigned char *buf, varint_t v);

/* Returns bytes used: 0 if max_len too small. */
size_t kyk_unpack_varint(const unsigned char *buf, varint_t *val);

size_t get_varint_size(const varint_t v);

size_t get_var_str_size(const var_str* vstr);

size_t kyk_pack_var_str(uint8_t* buf, const var_str* vstr);

var_str* kyk_new_var_str(const char* str);

void kyk_free_var_str(var_str* vstr);

#endif
