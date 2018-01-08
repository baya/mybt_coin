#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>

#include "kyk_utils.h"
#include "dbg.h"

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
    size_t i = 0;
    size_t dst_len = len * 2;

    if(strlen(hexstr) != dst_len){
	return -1;
    }

    for (i = 0; i < len; ++i) {
        const char hi = kyk_hex2byte(hexstr[i * 2]);
        const char lo = kyk_hex2byte(hexstr[i * 2 + 1]);

        buf[i] = hi * 16 + lo;
    }


    return 0;
}

size_t kyk_reverse_pack_chars(unsigned char *buf, const unsigned char *src, size_t count)
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


size_t kyk_pack_chars(unsigned char *buf, const unsigned char *src, size_t count)
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

char* kyk_pth_concat(const char *s1, const char *s2)
{
    /* first +1 for the '/' char, second +1 for the null-terminator */
    char *result = malloc(strlen(s1) + 1 + strlen(s2)+1);
    check(result != NULL, "failed to malloc");
    strcpy(result, s1);
    strcat(result, "/");
    strcat(result, s2);
    
    return result;
error:

    return NULL;
}


int kyk_detect_dir(const char *dir)
{
    struct stat st;
    int res = 0;

    if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode))
    {
        res = 1;
    } else {
	res = 0;
    }

    return res;
    
}

char* kyk_gethomedir(void)
{
    struct passwd* pwd;

    pwd = getpwuid(getuid());
    check(pwd != NULL, "failed to get pwd");

    return kyk_strdup(pwd -> pw_dir);

error:
    return NULL;
}

char* kyk_strdup(const char* str)
{
    void* ptr = strdup(str);
    check(ptr != NULL, "failed to dup string");
    
    return ptr;

error:
    return NULL;
}


char* kyk_asprintf(const char *fmt, ...)
{
    va_list args;
    char *ptr = NULL;
    int n = 0;

    va_start(args, fmt);
    n = vasprintf(&ptr, fmt, args);
    va_end(args);

    check(n != -1, "failed to vasprintf");

    return ptr;

error:
    return NULL;
}

char* bytes2hexstr(const uint8_t* buf, size_t buflen)
{
    char* str = NULL;
    size_t len = 0;
    int res = -1;

    len = buflen * 2 + 1;
    str = calloc(len, sizeof(*str));
    check(str, "Failed to bytes2hexstr: calloc failed");

    res = str_snprintf_bytes(str, len, buf, buflen);
    check(res == 0, "Failed to bytes2hexstr: str_snprintf_bytes failed");

    return str;

error:

    return NULL;
}


int str_snprintf_bytes(char        *str,
		       size_t       len,
		       const uint8_t *buf,
		       size_t       buflen)
{
    size_t idx = 0;
    size_t i;

    str[0] = '\0';
    
    for (i = 0; i < buflen; i++) {
	check(idx <= len, "str_snprintf_bytes: overflow len");
	idx += snprintf(str + idx, len - idx, "%02x", buf[i]);
    }

    return 0;

error:
    return -1;
}

int kyk_get_suffix_digest(const char* str, int* num)
{
    char tmp[11];
    size_t i = 0;
    size_t j = 0;
    size_t len = strlen(str);
    size_t max_size = sizeof(tmp) - 1;

    for(i = 0; i < len; i++){
	char c = str[i];
	if(isdigit(c)){
	    check(j < max_size, "over max size %lu", max_size);
	    tmp[j] = c;
	    j++;
	} else {
	    j = 0;
	}
    }

    *num = strtol(tmp, NULL, 10);

    return 0;

error:

    return -1;
}


int kyk_get_first_digest(const char* str, int* num)
{
    char tmp[11];
    size_t i = 0;
    size_t j = 0;
    size_t len = strlen(str);
    size_t max_size = sizeof(tmp) - 1;

    for(i = 0; i < len; i++){
	char c = str[i];
	if(isdigit(c)){
	    check(j < max_size, "over max size %lu", max_size);
	    tmp[j] = c;
	    j++;
	} else {
	    if(j > 0){
		break;
	    }
	}
    }

    *num = strtol(tmp, NULL, 10);
    
    return 0;

error:

    return -1;
}

int kyk_file_read_all(uint8_t** new_buf, FILE* fp, size_t* len)
{
    int res = -1;
    size_t blen = 0;
    size_t fcode = 0;
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    
    res = fseek(fp, 0L, SEEK_END);
    check(res == 0, "Failed to kyk_file_read_all: fseek failed");
    
    blen = ftell(fp);

    res = fseek(fp, 0L, SEEK_SET);
    check(res == 0, "Failed to kyk_file_read_all: fseek failed");

    if(blen == 0){
	if(len) *len = blen;
	return 0;
    }

    buf = calloc(blen, sizeof(*buf));
    check(buf, "Failed to kyk_file_read_all: buf calloc failed");

    bufp = buf;

    fcode = fread(bufp, sizeof(*bufp), blen, fp);
    check(fcode == blen, "Failed to kyk_file_read_all: fread failed");

    *new_buf = buf;
    
    if(len){
	*len = blen;
    }
    

    return 0;
error:
    if(buf) free(buf);
    return -1;
}
