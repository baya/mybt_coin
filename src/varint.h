#ifndef KYK_BITCOIN_VARINT_H
#define KYK_BITCOIN_VARINT_H

#define varint_t uint64_t

/* Returns bytes used (up to 9) */
size_t kyk_pack_varint(unsigned char *buf, varint_t v);

/* Returns bytes used: 0 if max_len too small. */
size_t kyk_unpack_varint(const unsigned char *buf, varint_t *val);

#endif
