#ifndef KYK_SC_OPCODE_H__
#define KYK_SC_OPCODE_H__

#include <openssl/sha.h>
#include <openssl/ripemd.h>


#define COINBASE_INX       0xffffffff
#define NULL_HASH          "0000000000000000000000000000000000000000000000000000000000000000"
#define MAX_COINBASE_SC_LEN 100
#define MAX_SC_PUB_LEN 1000
#define KYK_COINBASE_SEQ_NO 0xFFFFFFFF
#define KYK_COINBASE_PRE_TX_INX 0xffffffff
#define KYK_COINBASE_PRE_TX_BYTE 0x00

/* Constants */
#define OP_FALSE           0x00
#define OP_PUSHDATA0_START 0x01
#define OP_PUSHDATA0_END   0x4b
#define OP_PUSHDATA1       0x4c
#define OP_PUSHDATA2       0x4d
#define OP_PUSHDATA4       0x4e
#define OP_1NEGATE         0x4f
#define OP_TRUE            0x51
#define OP_2               0x52
#define OP_3               0x53
#define OP_4               0x54
#define OP_5               0x55
#define OP_6               0x56
#define OP_7               0x57
#define OP_8               0x58
#define OP_9               0x59
#define OP_10              0x5a
#define OP_11              0x5b
#define OP_12              0x5c
#define OP_13              0x5d
#define OP_14              0x5e
#define OP_15              0x5f
#define OP_16              0x60

/* Flow control */
#define OP_NOP    0x61
#define OP_IF     0x63
#define OP_NOTIF  0x64
#define OP_ELSE   0x67
#define OP_ENDIF  0x68
#define OP_VERIFY 0x69
#define OP_RETURN 0x6a

/* Stack */
#define OP_TOALTSTACK   0x6b
#define OP_FROMALTSTACK 0x6c
#define OP_IFDUP        0x73
#define OP_DEPTH        0x74
#define OP_DROP         0x75
#define OP_DUP          0x76
#define OP_NIP          0x77
#define OP_OVER         0x78
#define OP_PICK         0x79
#define OP_ROLL         0x7a
#define OP_ROT          0x7b
#define OP_SWAP         0x7c
#define OP_TUCK         0x7d
#define OP_2DROP        0x6d
#define OP_2DUP         0x6e
#define OP_3DUP         0x6f
#define OP_2OVER        0x70
#define OP_2ROT         0x71
#define OP_2SWAP        0x72

/* Splice */
#define OP_CAT    0x7e
#define OP_SUBSTR 0x7f
#define OP_LEFT   0x80
#define OP_RIGHT  0x81
#define OP_SIZE   0x82

/* Bitwise logic */
#define OP_INVERT      0x83
#define OP_AND         0x84
#define OP_OR          0x85
#define OP_XOR         0x86
#define OP_EQUAL       0x87
#define OP_EQUALVERIFY 0x88

/* Arithmetic */
#define OP_1ADD               0x8b
#define OP_1SUB               0x8c
#define OP_2MUL               0x8d
#define OP_2DIV               0x8e
#define OP_NEGATE             0x8f
#define OP_ABS                0x90
#define OP_NOT                0x91
#define OP_0NOTEQUAL          0x92
#define OP_ADD                0x93
#define OP_SUB                0x94
#define OP_MUL                0x95
#define OP_DIV                0x96
#define OP_MOD                0x97
#define OP_LSHIFT             0x98
#define OP_RSHIFT             0x99
#define OP_BOOLAND            0x9a
#define OP_BOOLOR             0x9b
#define OP_NUMEQUAL           0x9c
#define OP_NUMEQUALVERIFY     0x9d
#define OP_NUMNOTEQUAL        0x9e
#define OP_LESSTHAN           0x9f
#define OP_GREATERTHAN        0xa0
#define OP_LESSTHANOREQUAL    0xa1
#define OP_GREATERTHANOREQUAL 0xa2
#define OP_MIN                0xa3
#define OP_MAX                0xa4
#define OP_WITHIN             0xa5

/* Crypto */
#define OP_RIPEMD160           0xa6
#define OP_SHA1                0xa7
#define OP_SHA256              0xa8
#define OP_HASH160             0xa9
#define OP_HASH256             0xaa
#define OP_CODESEPARATOR       0xab
#define OP_CHECKSIG            0xac
#define OP_CHECKSIGVERIFY      0xad
#define OP_CHECKMULTISIG       0xae
#define OP_CHECKMULTISIGVERIFY 0xaf

/* Locktime */
#define OP_CHECKLOCKTIMEVERIFY 0xb1
#define OP_CHECKSEQUENCEVERIFY 0xb2

/* Pseudo-words */
#define OP_PUBKEYHASH    0xfd
#define OP_PUBKEY        0xfe
#define OP_INVALIDOPCODE 0xff

/* Reserved words */
#define OP_RESERVED  0x50
#define OP_VER       0x62
#define OP_VERIF     0x65
#define OP_VERNOTIF  0x66
#define OP_RESERVED1 0x89
#define OP_RESERVED2 0x8a
#define OP_NOP1      0xb0
#define OP_NOP9      0xb9

#define NO_FOUND_OPTCODE "NO_FOUND_OPTCODE"

#define  KYK_SC_STACK_BUF_SIZE 20

struct kyk_sc_stk_item {
    size_t len;
    uint8_t *val;
};

struct kyk_sc_stack {
    size_t hgt;
    struct kyk_sc_stk_item *top;
    struct kyk_sc_stk_item buf[KYK_SC_STACK_BUF_SIZE];
};


size_t p2pkh_sc_from_address(unsigned char *sc, const char *addr);
size_t kyk_combine_sc(uint8_t *sc,
		      uint8_t *sc_sig, size_t sc_sig_len,
		      uint8_t *sc_pubk, size_t sc_pubk_len);

int kyk_run_sc(uint8_t *sc, size_t sc_len, uint8_t *tx, size_t tx_len);


#endif
