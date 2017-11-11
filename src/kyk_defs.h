#ifndef __KYK_DEFS_H__
#define __KYK_DEFS_H__


#ifndef bool
typedef char bool;
#endif

#define FALSE   0
#define TRUE    1

#define DIGEST_SHA256_LEN       32
#define DIGEST_RIPEMD160_LEN    20

typedef struct {
    uint8_t data[DIGEST_SHA256_LEN];
} uint256;


typedef struct {
    uint8_t data[DIGEST_RIPEMD160_LEN];
} uint160;


#endif
