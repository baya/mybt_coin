#ifndef __KYK_UTILS_H
#define __KYK_UTILS_H

void kyk_print_hex(const char *label, const uint8_t *v, size_t len);
uint8_t kyk_hex2byte(const char ch);
void kyk_parse_hex(uint8_t *v, const char *str);
uint8_t *kyk_alloc_hex(const char *str, size_t *len);
void kyk_reverse(uint8_t *dst, size_t len);
size_t kyk_pack_chars(unsigned char *buf, const unsigned char *src, size_t count);
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, size_t len);
void print_bytes_in_hex(const unsigned char *buf, size_t len);
size_t kyk_reverse_pack_chars(unsigned char *buf, const unsigned char *src, size_t count);
void kyk_inline_print_hex(const unsigned char *buf, size_t len);
void kyk_copy_hex2bin(uint8_t *v, const char *str, size_t len);
int kyk_digest_eq(const void* lhs, const void* rhs, size_t count);
char* kyk_pth_concat(const char *s1, const char *s2);
int kyk_detect_dir(const char *dir);

#endif
