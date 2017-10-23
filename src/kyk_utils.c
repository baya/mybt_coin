#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "kyk_utils.h"

void kyk_print_hex(const char *label, const uint8_t *v, size_t len)
{
    size_t i;

    if(strlen(label) > 0){
	printf("%s: ", label);
    }
    
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}

uint8_t kyk_hex2byte(const char ch)
{
    if ((ch >= '0') && (ch <= '9')) {
        return ch - '0';
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + 10;
    }
    return 0;
}

void kyk_parse_hex(uint8_t *v, const char *str)
{
    const size_t count = strlen(str) / 2;
    size_t i;

    for (i = 0; i < count; ++i) {
        const char hi = kyk_hex2byte(str[i * 2]);
        const char lo = kyk_hex2byte(str[i * 2 + 1]);

        v[i] = hi * 16 + lo;
    }
}


void kyk_copy_hex2bin(uint8_t *v, const char *str, size_t len)
{
    const size_t count = strlen(str) / 2;
    size_t i;

    if(count > len){
	printf("kyk_copy_hex2bin error\n");
	exit(1);
    }

    for (i = 0; i < count; ++i) {
        const char hi = kyk_hex2byte(str[i * 2]);
        const char lo = kyk_hex2byte(str[i * 2 + 1]);

        v[i] = hi * 16 + lo;
    }
}


uint8_t *kyk_alloc_hex(const char *str, size_t *len)
{
    const size_t count = strlen(str) / 2;
    size_t i;

    uint8_t *v = malloc(count);

    for (i = 0; i < count; ++i) {
        const char hi = kyk_hex2byte(str[i * 2]);
        const char lo = kyk_hex2byte(str[i * 2 + 1]);

        v[i] = hi * 16 + lo;
    }

    *len = count;

    return v;
}



void kyk_reverse(uint8_t *dst, size_t len)
{
    size_t i;
    const size_t stop = len >> 1;
    for (i = 0; i < stop; ++i) {
        uint8_t *left = dst + i;
        uint8_t *right = dst + len - i - 1;
        const uint8_t tmp = *left;
        *left = *right;
        *right = tmp;
    }
}


void print_bytes_in_hex(const unsigned char *buf, size_t len)
{
    size_t i = 0;
    for(i=0; i < len; i++){
	printf("%02x", buf[i]);
    }
    printf("\n");
}

void kyk_inline_print_hex(const unsigned char *buf, size_t len)
{
    size_t i = 0;
    
    for(i=0; i < len; i++){
	printf("%02x", buf[i]);
    }
}

    
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, size_t len)
{
    size_t count = 0;
    size_t dst_len = len * 2;
    int ret;

    if(strlen(hexstr) != dst_len){
	return -1;
    }

    for(count = 0; count < len; count++){
	ret = sscanf(hexstr, "%2hhx", buf);
	if(ret < 1){
	    return -1;
	}
	buf += 1;
	hexstr += 2;
    }

    return 0;
}

size_t kyk_reverse_pack_chars(unsigned char *buf, unsigned char *src, size_t count)
{
    size_t size = 0;
    int i = 0;

    for(i = count-1; i >= 0; i--){
	*buf = src[i];
	buf++;
	size += 1;
    }

    return size;
}


size_t kyk_pack_chars(unsigned char *buf, unsigned char *src, size_t count)
{
    size_t size = 0;
    size_t i = 0;

    for(i=0; i < count; i++){
	*buf = src[i];
	buf++;
	size += 1;
    }

    return size;
}

int kyk_digest_eq(const void* lhs, const void* rhs, size_t count)
{
    int res = 0;
    res = memcmp(lhs, rhs, count) == 0 ? 1 : 0;

    return res;
}
