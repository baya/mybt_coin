#include <string.h>
#include <stdlib.h>
#include "kyk_base58.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "dbg.h"

static const char kyk_base58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static int decode_char(char c, const char *enc);

char *kyk_base58(const uint8_t *bytes, size_t len)
{
    size_t str_len;
    char *str;
    BN_CTX *ctx;
    BIGNUM *base, *x, *r;
    size_t i = 0;
    size_t j = 0;
    
    str_len = len * 138 / 100 + 2;
    str = calloc(str_len, sizeof(char));

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    base = BN_new();
    x = BN_new();
    r = BN_new();
    
    /* 将 58 赋值给 base, 即 base 是一个值为 58 的大数*/
    BN_set_word(base, 58);

    /* 将 bytes 转换为一个大数, 赋值给 x*/
    BN_bin2bn(bytes, len, x);
    
    i = 0;
    while (!BN_is_zero(x)) {
    
        /*
	* int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
        *            BN_CTX *ctx);
	*
	* ("dv=a/d, rem=a%d")
        *
	*  第三个 x 除以 base, 计算的结果放在第一个 x 里, 余数放在 r 里
	*/
        BN_div(x, r, x, base, ctx);

	/* BN_get_word 用于取出大数的值, 这里是取出余数 r 的值 */
        str[i] = kyk_base58_alphabet[BN_get_word(r)];
        ++i;
    }
    for (j = 0; j < len; ++j) {
        if (bytes[j] != 0x00) {
            break;
        }
        str[i] = kyk_base58_alphabet[0];
        ++i;
    }
    kyk_reverse((uint8_t *)str, i);
    
    BN_clear_free(r);
    BN_clear_free(x);
    BN_free(base);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return str;
}

char *kyk_base58check(uint8_t addrtype, const uint8_t *bytes, size_t len)
{
    size_t check_len;
    uint8_t *check;
    uint8_t digest[32];
    char *str;

    /* prefix + payload + checksum */
    check_len = 1 + len + 4;
    check = calloc(check_len, sizeof(char));
    check[0] = addrtype;
    memcpy(check + 1, bytes, len);

    kyk_dgst_hash256(digest, check, len + 1);
    
    memcpy(check + 1 + len, digest, 4);

    str = kyk_base58(check, check_len);
    free(check);

    return str;
}

int raw_decode_base58(BIGNUM *bn, const char *src, size_t len)
{
    int base = 58;
    char current;
    int rem;

    BN_zero(bn);

    while(len){
	current = *src;
	rem = decode_char(current, kyk_base58_alphabet);
	if(rem < 0){
	    BN_free(bn);
	    return -1;
	}

	BN_mul_word(bn, base);
	BN_add_word(bn, rem);

	src++;
	len--;
    }

    return 1;

}

int kyk_base58_decode_check(const char* src, size_t src_len, uint8_t** dst, size_t* dst_len)
{
    BIGNUM bn;
    size_t bn_len = 0;
    uint8_t* buf = NULL;

    check(dst, "dst can not be NULL");

    BN_init(&bn);

    raw_decode_base58(&bn, src, src_len);

    bn_len = BN_num_bytes(&bn);
    *dst_len = bn_len - 1 - 4;
    
    *dst = calloc(*dst_len, sizeof(uint8_t));
    check(*dst, "failed to calloc");
    
    buf = calloc(bn_len, sizeof(*buf));
    check(dst, "failed to calloc");
    
    BN_bn2bin(&bn, buf);
    memcpy(*dst, buf + 1, *dst_len);

    free(buf);
    BN_free(&bn);

    return 0;

error:
    if(buf) free(buf);
    if(*dst) free(*dst);
    BN_free(&bn);
    return -1;
}


void base58_get_checksum(uint8_t csum[4], const uint8_t *buf, size_t buflen)
{
    //struct protocol_double_sha sha_result;
    uint8_t digst[32];

    /* Form checksum, using double SHA2 (as per bitcoin standard) */
    kyk_dgst_hash256(digst, buf, buflen);

    /* Use first four bytes of that as the checksum. */
    memcpy(csum, digst, 4);
}

int validate_base58_checksum(const uint8_t *buf, size_t buflen)
{
    uint8_t csum[4];

    base58_get_checksum(csum, buf, buflen);
    if (memcmp(csum, buf + 1 + RIPEMD160_DIGEST_LENGTH, sizeof(csum)) != 0){
	return -1;
    }

    return 1;
    
}

static int decode_char(char c, const char *enc)
{
    const char *pos = strchr(enc, c);
    if (!pos)
	return -1;
    return pos - enc;
}

