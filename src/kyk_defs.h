#ifndef __KYK_DEFS_H__
#define __KYK_DEFS_H__

#if defined __UINT32_MAX__ || UINT32_MAX
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long long uint64_t;
#endif


#ifndef bool
typedef char bool;
#endif

#define FALSE   0
#define TRUE    1

enum kyk_hashtype{
    HTYPE_SIGHASH_ALL = 1,
    HTYPE_SIGHASH_NONE = 2,
    HTYPE_SIGHASH_SINGLE = 3,
    HTYPE_SIGHASH_ANYONECANPAY = 128
};

#define DIGEST_SHA256_LEN       32
#define DIGEST_RIPEMD160_LEN    20

#define KYK_BASE_BTC_COUNAT     100
#define KYK_BASE_DIFFT_BITS     0x1f00ffff
#define KYK_BASE_BLK_VERSION    1
#define KYK_DEFAULT_PUBKEY_NAME "key0.pubkey"
#define KYK_DEFAULT_NOTE        "voidcoin"


#define NORMALLY_TX_SEQ_NO      0xFFFFFFFF
#define MORMALLY_TX_LOCK_TIME   0
#define COINBASE_PRE_TXID       "0000000000000000000000000000000000000000000000000000000000000000"
#define COINBASE_INX            0xffffffff

/* 1 BTC = 10 ** 8 Satoshi */
#define ONE_BTC_COIN_VALUE 100000000

/* Total BTC Value */
#define TOTAL_BTC_VALUE    2000 * 10000 * ONE_BTC_COIN_VALUE

/* miner fee */
#define KYK_MINER_FEE 0

typedef struct {
    uint8_t data[DIGEST_SHA256_LEN];
} uint256;


typedef struct {
    uint8_t data[DIGEST_RIPEMD160_LEN];
} uint160;




#endif
