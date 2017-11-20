#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_base58.h"
#include "kyk_script.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "beej_pack.h"
#include "kyk_ecdsa.h"

#define TX_BUF_SIZE 2000

static size_t build_p2pkh_sc_pubk(unsigned char *buf, const unsigned char *pkh, size_t pkh_len);
static int pubk_hash_from_address(unsigned char *pubk_hash, size_t pkh_len, const char *addr);
static int is_sc_na_const(uint8_t opcode);
static void init_sc_stack(struct kyk_sc_stack *stk);
static int is_sc_na_const(uint8_t opcode);
static void kyk_sc_op_dup(struct kyk_sc_stack *stk);
static void kyk_sc_op_hash160(struct kyk_sc_stack *stk);
static struct kyk_sc_stk_item * kyk_sc_pop_stack(struct kyk_sc_stack *stk);
static void free_sc_stk_item(struct kyk_sc_stk_item *item);
static void kyk_sc_stack_push(struct kyk_sc_stack *stk, uint8_t *sc, size_t len);
static int kyk_sc_op_eq_verify(struct kyk_sc_stack *stk);
static int kyk_sc_op_eq(struct kyk_sc_stack *stk);
static int kyk_sc_op_checksig(struct kyk_sc_stack *stk, uint8_t *tx, size_t tx_len);
static int kyk_sc_cmpitem(const struct kyk_sc_stk_item *item1,
			  const struct kyk_sc_stk_item *item2);
static void free_sc_stack(struct kyk_sc_stack *stk);

int build_p2pkh_sc_from_pubkey()
{
    return 0;
}


size_t p2pkh_sc_from_address(unsigned char *sc, const char *addr)
{
    uint8_t pubk_hash[RIPEMD160_DIGEST_LENGTH];
    size_t len;
    
    if(pubk_hash_from_address(pubk_hash, sizeof(pubk_hash), addr) < 0){
	return -1;
    }
    
    len = build_p2pkh_sc_pubk(sc, pubk_hash, sizeof(pubk_hash));

    return len;
}

int pubk_hash_from_address(unsigned char *pubk_hash, size_t pkh_len, const char *addr)
{
    BIGNUM bn;
    size_t len;
    uint8_t buf[1 + RIPEMD160_DIGEST_LENGTH + 4];

    BN_init(&bn);
    raw_decode_base58(&bn, addr, strlen(addr));

    len = BN_num_bytes(&bn);
    memset(buf, 0, sizeof(buf));
    BN_bn2bin(&bn, buf + sizeof(buf) - len);

    BN_free(&bn);

    if(validate_base58_checksum(buf, 1 + RIPEMD160_DIGEST_LENGTH) < 0){
	fprintf(stderr, "address base58 checksum failed\n");
	return -1;
    }

    memcpy(pubk_hash, buf+1, pkh_len);

    return 1;

}

/* 76       A9             14                                                        */
/* OP_DUP OP_HASH160    Bytes to push                                                */
/* 89 AB CD EF AB BA AB BA AB BA AB BA AB BA AB BA AB BA AB BA   88         AC       */
/*                       Data to push                     OP_EQUALVERIFY OP_CHECKSIG */
size_t build_p2pkh_sc_pubk(unsigned char *sc, const unsigned char *pkh, size_t pkh_len)
{
    size_t count = 0;
    
    *sc = OP_DUP;
    count += 1;

    sc++;
    *sc = OP_HASH160;
    count += 1;

    sc++;
    *sc = (uint8_t) pkh_len;
    count += 1;

    sc++;
    memcpy(sc, pkh, pkh_len);
    count += pkh_len;
    
    sc += pkh_len;
    *sc = OP_EQUALVERIFY;
    count += 1;

    sc++;
    *sc = OP_CHECKSIG;
    count += 1;

    return count;
}


size_t kyk_combine_sc(uint8_t *sc,
		    uint8_t *sc_sig, size_t sc_sig_len,
		    uint8_t *sc_pubk, size_t sc_pubk_len)
{
    size_t count = 0;
    size_t i = 0;
    
    for(i=0; i < sc_sig_len; i++){
	*sc = sc_sig[i];
	sc++;
	count++;
    }

    for(i=0; i < sc_pubk_len; i++){
	*sc = sc_pubk[i];
	sc++;
	count++;
    }

    return count;
}

int kyk_run_sc(uint8_t *sc, size_t sc_len, uint8_t *tx, size_t tx_len)
{
    struct kyk_sc_stack stk;
    uint8_t opcode;
    size_t count = 0;

    init_sc_stack(&stk);

    while(count < sc_len){
	opcode = *sc;
	if(is_sc_na_const(opcode) == 1){
	    sc++;
	    count += 1;
	    kyk_sc_stack_push(&stk, sc, opcode);
	    sc += opcode;
	    count += opcode;
	} else {
	    switch (opcode){
	    case OP_DUP:
		sc++;
		count += 1;
		kyk_sc_op_dup(&stk);
		break;
	    case OP_HASH160:
		sc++;
		count += 1;
		kyk_sc_op_hash160(&stk);
		
		break;
	    case OP_EQUALVERIFY:
		sc++;
		count += 1;
		if(kyk_sc_op_eq_verify(&stk) < 1){
		    free_sc_stack(&stk);
		    return 0;
		}
		
		break;
	    case OP_CHECKSIG:
		sc++;
		count += 1;
		if(kyk_sc_op_checksig(&stk, tx, tx_len) < 1){
		    free_sc_stack(&stk);
		    return 0;
		}
		break;
	    default:		
	        fprintf(stderr, "Invalid Op Code: %x\n", opcode);
		return 0;
		break;
	    }
	}
    }

    free_sc_stack(&stk);    
    return 1;
    
}

void init_sc_stack(struct kyk_sc_stack *stk)
{
    stk -> hgt = 0;
    stk -> top = NULL;
}

/*
 * The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the end) are hashed.
 * The signature used by OP_CHECKSIG must be a valid signature for this hash and public key.
 * If it is, 1 is returned, 0 otherwise.
 *
 * An array of bytes is constructed from the serialized txCopy appended by four bytes for the hash type.
 * This array is sha256 hashed twice, then the public key is used to check the supplied signature against the hash.
 * The secp256k1 elliptic curve is used for the verification with the given public key.
 *
 */
int kyk_sc_op_checksig(struct kyk_sc_stack *stk, uint8_t *tx, size_t tx_len)
{
    int ret_code = 0;
    struct kyk_sc_stk_item *top_cpy = stk -> top;
    uint8_t *sig, *pubkey;
    size_t sig_len, pubkey_len;
    uint8_t htype;
    uint8_t tx_buf[TX_BUF_SIZE];
    size_t size, buf_len;
    uint8_t der_sig[100];

    pubkey = top_cpy -> val;
    pubkey_len = top_cpy -> len;
    top_cpy--;
    sig = top_cpy -> val;
    sig_len = top_cpy -> len;

    htype = *(sig + sig_len - 1); /* sig 的末尾一个字节是 hash type */
    memcpy(tx_buf, tx, tx_len);
    size = beej_pack(tx_buf + tx_len, "<L", (uint32_t) htype);
    buf_len = tx_len + size;

    memcpy(der_sig, sig, sig_len - 1);
    ret_code = kyk_ec_sig_hash256_verify(tx_buf, buf_len,
					 der_sig, sig_len-1,
					 pubkey, pubkey_len);
    stk -> top--;
    stk -> top--;
    stk -> hgt -= 2;

    
    return ret_code;
}

/* The data is hashed twice: first with SHA-256 and then with RIPEMD-160. */
void kyk_sc_op_hash160(struct kyk_sc_stack *stk)
{
    struct kyk_sc_stk_item *item = kyk_sc_pop_stack(stk);
    uint8_t digest[20]; /* for ripemd-160 digest */

    kyk_dgst_hash160(digest, item -> val, item -> len);
    free_sc_stk_item(item);
    kyk_sc_stack_push(stk, digest, sizeof(digest));
}

/*
 * OP_EQUALVERIFY:
 * Same as OP_EQUAL, but runs OP_VERIFY afterward.
 * OP_EQUAL: Returns 1 if the inputs are exactly equal, 0 otherwise.
 * OP_VERIFY: Marks transaction as invalid if top stack value is not true.
 * 
 */
int kyk_sc_op_eq_verify(struct kyk_sc_stack *stk)
{
    int ret_code = 0;
    ret_code = kyk_sc_op_eq(stk);

    return ret_code;
}

/*
 * OP_EQUAL: Returns 1 if the inputs are exactly equal, 0 otherwise. 
 */
int kyk_sc_op_eq(struct kyk_sc_stack *stk)
{
    int ret_code = 0;
    struct kyk_sc_stk_item *item1 = stk -> top;
    struct kyk_sc_stk_item *item2 = stk -> top - 1;

    if(kyk_sc_cmpitem(item1, item2) > 0){
	ret_code = 1;
	stk -> top--;
	stk -> top--;
	stk -> hgt -= 2;
    }

    return ret_code;
}

int kyk_sc_cmpitem(const struct kyk_sc_stk_item *item1,
		    const struct kyk_sc_stk_item *item2)
{
    int ret_code = 0;
    if(item1 -> len == item2 -> len && memcmp(item1 -> val, item2 -> val, item1 -> len) == 0){
	ret_code = 1;
    }

    return ret_code;
}

struct kyk_sc_stk_item * kyk_sc_pop_stack(struct kyk_sc_stack *stk)
{
    struct kyk_sc_stk_item *item;

    item = stk -> top;
    stk -> top--;
    stk -> hgt--;

    return item;
}

void kyk_sc_op_dup(struct kyk_sc_stack *stk)
{
    struct kyk_sc_stk_item *item;

    item = stk -> top;
    kyk_sc_stack_push(stk, item -> val, item -> len);
}


void kyk_sc_stack_push(struct kyk_sc_stack *stk, uint8_t *sc, size_t len)
{
    struct kyk_sc_stk_item *item;
    
    if(stk -> top == NULL){
	stk -> top = stk -> buf;
    } else {
	stk -> top++;
    }

    item = stk -> top;
    item -> len = len;
    item -> val = malloc(len * sizeof(uint8_t));
    memcpy(item -> val, sc, len);

    stk -> hgt++;
}

int is_sc_na_const(uint8_t opcode)
{
  if(opcode >= OP_PUSHDATA0_START && opcode <= OP_PUSHDATA0_END){
    return 1;
  } else {
    return 0;
  }
}

void free_sc_stack(struct kyk_sc_stack *stk)
{
    size_t i = 0;
    for(i=0; i < stk -> hgt; i++){
	free_sc_stk_item(stk -> top);
	stk -> top--;
    }
}

void free_sc_stk_item(struct kyk_sc_stk_item *item)
{
    free(item -> val);
}




