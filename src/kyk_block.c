#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "kyk_tx.h"
#include "kyk_block.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_buff.h"
#include "kyk_mkl_tree.h"
#include "kyk_sha.h"
#include "kyk_hash_nonce.h"
#include "kyk_validate.h"
#include "dbg.h"

int kyk_get_blkself_size(const struct kyk_block* blk,
			 size_t* blkself_size)
{
    size_t len = 0;
    size_t blk_size = 0;
    int res = -1;

    check(blk, "Failed to kyk_get_blk_selfsize: blk is NULL");

    len += sizeof(blk -> magic_no);
    len += sizeof(blk -> blk_size);
    res = kyk_get_blk_size(blk, &blk_size);
    check(res == 0, "Failed to kyk_get_blk_selfsize: kyk_get_blk_size failed");

    *blkself_size = len + blk_size;

    return 0;

error:

    return -1;
}

int kyk_set_blkself_info(struct kyk_block* blk)
{
    int res = -1;
    size_t len = 0;
    
    blk -> magic_no = KYK_BLK_MAGIC_NO;
    res = kyk_get_blk_size(blk, &len);
    check(res == 0, "Failed to kyk_set_blkself_info: kyuk_get_blkself_size failed");

    blk -> blk_size = (uint32_t)len;
    
    return 0;
error:
    return -1;
}

int kyk_get_blk_size(const struct kyk_block* blk,
		     size_t* blk_size)
{
    const struct kyk_tx* tx = NULL;
    size_t len = 0;
    size_t tx_size = 0;
    size_t i = 0;
    int res = -1;

    check(blk, "kyk_get_blk_size failed: blk si NULL");
    check(blk -> hd, "Failed to kyk_get_blk_size: blk -> hd is NULL");
    check(blk -> tx, "Failed to kyk_get_blk_size: blk -> tx is NULL");
    check(blk -> tx_count > 0, "Failed to kyk_get_blk_size: blk -> tx_count is invalid");

    tx = blk -> tx;
    len += KYK_BLK_HD_LEN;
    len += get_varint_size(blk -> tx_count);

    for(i = 0; i < blk -> tx_count; i++){
	res = kyk_get_tx_size(tx + i, &tx_size);
	check(res == 0, "Failed to kyk_get_blk_size: kyk_get_tx_size failed");
	len += tx_size;
    }
    
    *blk_size = len;
    
    return 0;

error:

    return -1;
}

int kyk_init_block(struct kyk_block *blk)
{
    check(blk, "Failed to init_block: blk is NULL");
    
    blk -> hd = malloc(sizeof(struct kyk_blk_header));
    check(blk -> hd, "Failed to init_block: blk -> hd malloc failed");
    
    blk -> tx = malloc(sizeof(struct kyk_tx));
    check(blk -> tx, "Failed to init_block: blk -> tx malloc failed");

    return 0;

error:

    return -1;
}

int kyk_deseri_block(struct kyk_block* blk,
		     const uint8_t* buf,
		     size_t* checknum)
{

    const uint8_t* bufp = NULL;
    int res = -1;
    size_t len = 0;

    check(blk, "Failed to kyk_deseri_block: blk is NULL");
    check(blk -> hd == NULL, "Failed to kyk_deseri_block: blk -> hd should be NULL");
    check(buf, "Failed to kyk_deseri_new_block: buf is NULL");

    bufp = buf;

    blk -> hd = calloc(1, sizeof(*blk -> hd));
    check(blk -> hd, "Failed to kyk_parse_block: blk -> hd calloc failed");

    res = kyk_deseri_blk_header(blk -> hd, buf, &len);
    check(res == 0, "Failed to kyk_deseri_new_block: kyk_deseri_blk_header failed");
    bufp += len;

    len = kyk_unpack_varint(bufp, &blk -> tx_count);
    check(len > 0, "Failed to kyk_deseri_block: kyk_unpack_varint failed");
    check(blk -> tx_count > 0, "Failed to kyk_deseri_block: blk -> tx_count is invalid");
    bufp += len;

    blk -> tx = calloc(blk -> tx_count, sizeof(*blk -> tx));
    check(blk -> tx, "Failed to kyk_deseri_block: blk -> tx calloc failed");

    res = kyk_deseri_tx_list(blk -> tx, blk -> tx_count, bufp, &len);
    check(res == 0, "Failed to kyk_deseri_new_block: kyk_deseri_tx_list failed");
    bufp += len;

    if(checknum){
	*checknum = bufp - buf;
    }

    return 0;

error:

    return -1;
}

/* buf should not have Magic No and Blocksize */
int kyk_deseri_new_block(struct kyk_block** new_blk,
			 const uint8_t* buf,
			 size_t* checknum)
{
    struct kyk_block* blk = NULL;
    const uint8_t* bufp = NULL;
    int res = -1;

    check(new_blk, "Failed to kyk_deseri_new_block: new_blk is NULL");    
    check(buf, "Failed to kyk_deseri_new_block: buf is NULL");

    blk = calloc(1, sizeof(*blk));
    check(blk, "Failed to kyk_deseri_new_block: blk is NULL");

    bufp = buf;

    res = kyk_deseri_block(blk, bufp, checknum);
    check(res == 0, "Failed to kyk_deseri_new_block: kyk_deseri_block failed");

    *new_blk = blk;
    
    return 0;

error:

    if(blk){
	kyk_free_block(blk);
    }
    return -1;

}


size_t kyk_seri_blk_hd(uint8_t *buf, const struct kyk_blk_header *hd)
{
    size_t len = 0;
    size_t total = 0;

    len = beej_pack(buf, "<L", hd -> version);
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> tts);
    buf += len;
    total += len;
    
    len = beej_pack(buf, "<L", hd -> bts);
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> nonce);
    buf += len;
    total += len;

    return total;
}


int kyk_seri_blk_hd_chain(struct kyk_bon_buff** bbuf,
			  const struct kyk_blk_hd_chain* hd_chain)
{
    struct kyk_bon_buff* bufp = NULL;
    struct kyk_blk_header* hd = NULL;
    uint8_t* buf_base = NULL;
    size_t chain_len = 0;
    size_t hd_len = 0;
    size_t i = 0;

    check(bbuf, "Failed to kyk_seri_blk_hd_chain: bbuf is NULL");
    check(hd_chain, "Failed to kyk_seri_blk_hd_chain: hd_chain is NULL");

    bufp = calloc(1, sizeof(*bufp));
    check(bufp, "Failed to kyk_seri_blk_hd_chain: bufp calloc failed");

    chain_len = hd_chain -> len;

    check(chain_len > 0, "Failed to kyk_seri_blk_hd_chain: chain_len is invalid");

    bufp -> len = chain_len * KYK_BLK_HD_LEN;
    bufp -> base = calloc(bufp -> len, sizeof(*bufp -> base));
    check(bufp -> base, "Failed to kyk_seri_blk_hd_chain: bufp -> base calloc failed");

    buf_base = bufp -> base;
    hd = hd_chain -> hd_list;

    for(i = 0; i < hd_chain -> len; i++){
	hd_len = kyk_seri_blk_hd(buf_base, hd);
	check(hd_len == KYK_BLK_HD_LEN, "Failed to kyk_seri_blk_hd_chain: kyk_ser_blk_hd failed");
	buf_base += hd_len;
	hd++;
    }

    *bbuf = bufp;
    
    return 0;
    
error:
    if(bufp) free_kyk_bon_buff(bufp);
    return -1;
}

int kyk_deseri_blk_hd_chain(struct kyk_blk_hd_chain** hd_chain,
			    const uint8_t* buf,
			    size_t buf_len)
{
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_blk_header* hd = NULL;
    const uint8_t* bufp = NULL;
    int hd_chain_len = 0;
    int i = 0;
    size_t hd_len = 0;
    int res = -1;

    check(hd_chain, "Failed to kyk_deseri_blk_hd_chain: hd_chain is NULL");
    check(buf, "Failed to kyk_deseri_blk_hd_chain: buf is NULL");

    hd_chain_len = buf_len / KYK_BLK_HD_LEN;
    check(hd_chain_len >= 1, "Failed to kyk_deseri_blk_hd_chain: invalid hd_count");

    res = kyk_init_blk_hd_chain(&hdc);
    check(res == 0, "Failed to kyk_deseri_blk_hd_chain: kyk_init_blk_hd_chain failed");

    hd = calloc(hd_chain_len, sizeof(*hd));
    check(hd, "Failed to kyk_deseri_blk_hd_chain: hd calloc failed");

    hdc -> hd_list = hd;
    bufp = buf;

    for(i = 0; i < hd_chain_len; i++){
	res = kyk_deseri_blk_header(hd, bufp, &hd_len);
	check(res == 0, "Failed to kyk_deseri_blk_hd_chain: kyk_deseri_blk_header failed");
	
	res = kyk_validate_blk_header(hdc, hd);
	check(res == 0, "Failed to kyk_deseri_blk_hd_chain: kyk_validate_blk_header failed");
	
	bufp += hd_len;
	hdc -> len += 1;
	hd += 1;
    }

    *hd_chain = hdc;

    return 0;
    
error:
    if(hdc) kyk_free_blk_hd_chain(hdc);
    return -1;
}

int kyk_deseri_blk_header(struct kyk_blk_header *hd,
			  const uint8_t *buf,
			  size_t* len)
{
    unsigned char* bufp = NULL;

    check(hd, "Failed to kyk_deseri_blk_header: hd is NULL");
    
    bufp = (unsigned char*)buf;
    check(bufp, "Failed to kyk_unpack_blk_header: bufp is NULL");

    beej_unpack(bufp, "<L", &hd -> version);
    bufp += sizeof(hd -> version);

    kyk_reverse_pack_chars(hd -> pre_blk_hash, bufp, sizeof(hd -> pre_blk_hash));
    bufp += sizeof(hd -> pre_blk_hash);

    kyk_reverse_pack_chars(hd -> mrk_root_hash, bufp, sizeof(hd -> mrk_root_hash));
    bufp += sizeof(hd -> mrk_root_hash);

    beej_unpack(bufp, "<L", &hd -> tts);
    bufp += sizeof(hd -> tts);

    beej_unpack(bufp, "<L", &hd -> bts);
    bufp += sizeof(hd -> bts);

    beej_unpack(bufp, "<L", &hd -> nonce);
    bufp += sizeof(hd -> nonce);

    *len = bufp - buf;

    return 0;

error:

    return -1;
}

int kyk_blk_hash256(uint8_t* digest, const struct kyk_blk_header* hd)
{
    uint8_t buf[KYK_BLK_HD_LEN];
    size_t len = 0;

    check(digest, "Failed to kyk_blk_hash256: digest is NULL");
    
    len = kyk_seri_blk_hd(buf, hd);
    check(len == KYK_BLK_HD_LEN, "Failed to kyk_blk_hash256: kyk_seri_blk_hd failed");

    kyk_dgst_hash256(digest, buf, KYK_BLK_HD_LEN);
    kyk_reverse(digest, SHA256_DIGEST_LENGTH);

    return 0;

error:

    return -1;
}

size_t kyk_seri_blk_hd_without_nonce(uint8_t *buf, const struct kyk_blk_header *hd)
{
    size_t len = 0;
    size_t total = 0;

    len = beej_pack(buf, "<L", hd -> version);
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> tts);
    buf += len;
    total += len;
    
    len = beej_pack(buf, "<L", hd -> bts);
    buf += len;
    total += len;

    return total;
}

void kyk_free_block(struct kyk_block *blk)
{
    if(blk){
	
	if(blk -> hd) {
	    free(blk -> hd);
	    blk -> hd = NULL;
	}
	
	if(blk -> tx) {
	    kyk_free_tx(blk -> tx);
	    blk -> tx = NULL;
	}

	free(blk);
	blk = NULL;
    }
}


int kyk_seri_blk(uint8_t* buf, const struct kyk_block* blk, size_t* check_size)
{
    size_t len = 0;
    size_t blk_size = 0;
    size_t i = 0;
    struct kyk_blk_header* hd = NULL;
    struct kyk_tx* tx = NULL;
    uint8_t *bufp = NULL;

    check(buf, "Failed to kyk_seri_blk: buf is NULL");
    check(blk, "Failed to kyk_seri_blk: blk is NULL");

    bufp = buf;
    hd = blk -> hd;
    tx = blk -> tx;
    
    len = kyk_seri_blk_hd(bufp, hd);
    bufp += len;
    blk_size += len;

    len = kyk_pack_varint(bufp, blk -> tx_count);
    bufp += len;
    blk_size += len;

    for(i = 0; i < blk -> tx_count; i++){
	len = kyk_seri_tx(bufp, tx + i);
	bufp += len;
	blk_size += len;
    }

    *check_size = blk_size;

    return 0;

error:

    return -1;

}

int kyk_seri_blkself(uint8_t* buf, const struct kyk_block* blk, size_t* check_size)
{
    size_t len = 0;
    size_t total_len = 0;
    uint8_t *bufp = NULL;
    int res = -1;

    check(buf, "Failed to kyk_seri_blkself: buf is NULL");
    check(blk, "Failed to kyk_seri_blkself: blk is NULL");

    bufp = buf;
    
    len = beej_pack(bufp, "<L", blk -> magic_no);
    bufp += len;
    total_len += len;
    
    len = beej_pack(bufp, "<L", blk -> blk_size);
    bufp += len;
    total_len += len;

    res = kyk_seri_blk(bufp, blk, &len);
    check(res == 0, "Failed to kyk_seri_blkself: kyk_seri_blk failed");
    check(len == blk -> blk_size, "Failed to kyk_seri_blkself: kyk_seri_blk failed");
    total_len += len;
    

    *check_size = total_len;

    return 0;

error:
    return -1;
}

/* we don't pass nonce here, because noce is computed by mining */
struct kyk_blk_header* kyk_make_blk_header(struct kyk_tx* tx_list,
					   varint_t tx_count,
					   uint32_t version,
					   uint8_t* pre_blk_hash,
					   uint32_t tts,
					   uint32_t bts)
{
    struct kyk_blk_header* hd = NULL;
    struct kyk_mkltree_level* mkl_root = NULL;

    check(tx_list, "Failed to kyk_make_blk_header: tx_list is NULL");

    hd = calloc(1, sizeof(struct kyk_blk_header));
    check(hd, "Failed to kyk_make_blk_header: calloc failed");

    hd -> version = version;
    memcpy(hd -> pre_blk_hash, pre_blk_hash, sizeof(hd -> pre_blk_hash));

    mkl_root = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_root, "Failed to kyk_make_blk_header: kyk_make_mkl_tree_root_from_tx_list failed");

    memcpy(hd -> mrk_root_hash, mkl_root -> nd -> bdy, sizeof(hd -> mrk_root_hash));

    hd -> tts = tts;
    hd -> bts = bts;
    hd -> nonce = 0;

    kyk_free_mkl_tree(mkl_root);
    mkl_root = NULL;

    return hd;

error:
    if(mkl_root) kyk_free_mkl_tree(mkl_root);
    return NULL;
}


int kyk_make_block(struct kyk_block** new_blk,
		   struct kyk_blk_header* blk_hd,
		   struct kyk_tx* tx_list,
		   varint_t tx_count
    )
{
    struct kyk_block* blk = NULL;
    size_t blk_size = 0;
    int res = -1;

    check(new_blk, "Failed to kyk_make_block: blk is NULL");
    check(blk_hd, "Failed to kyk_make_block: blk_hd is NULL");
    check(tx_list, "Failed to kyk_make_block: tx_list is NULL");

    blk = calloc(1, sizeof(*blk));
    check(blk, "Failed to kyk_make_block: blk calloc failed");

    blk -> magic_no = KYK_BLK_MAGIC_NO;
    blk -> blk_size = 0;
    blk -> hd = blk_hd;
    blk -> tx_count = tx_count;
    blk -> tx = tx_list;

    res = kyk_get_blk_size(blk, &blk_size);
    check(res == 0, "Failed to kyk_make_block: kyk_get_blk_size failed");
    blk -> blk_size = blk_size;

    *new_blk = blk;
    
    return 0;

error:
    if(blk) free(blk);
    return -1;
}

/* make block which contains only one coinbase Tx */
int kyk_make_coinbase_block(struct kyk_block** new_blk,
			    const struct kyk_blk_hd_chain* hd_chain,
			    const char* note,
			    const uint8_t* pubkey,
			    size_t pub_len)
{
    struct kyk_block* blk = NULL;
    struct kyk_blk_header* prev_hd = NULL;
    struct kyk_blk_header* hd = NULL;
    struct kyk_tx* tx = NULL;

    /* TODO: coinbase Tx out value shoud be adjusted according to the block chain height */
    uint64_t btc_count = KYK_BASE_BTC_COUNAT;
    uint64_t outValue = ONE_BTC_COIN_VALUE * btc_count;

    uint8_t pre_blk_hash[32];

    /* timestamp */
    uint32_t tts;

    /* TODO: encoded target should adjust automatically according to the block mean generated time */
    uint32_t bts = 0x1f00ffff;

    /* Block version number */
    uint32_t version = 1;

    /* Tx count: coinbase block contains only 1 coinbase Tx */
    varint_t tx_count = 1;
    
    int res = -1;

    check(new_blk, "Failed to kyk_make_coinbase_block: blk is NULL");
    check(hd_chain, "Failed to kyk_make_coinbase_block: hd_chain is NULL");
    check(note, "Failed to kyk_make_coinbase_block: note is NULL");
    check(pubkey, "Failed to kyk_make_coinbase_block: pubkey is NULL");

    res = kyk_make_coinbase_tx(&tx, note, outValue, pubkey, pub_len);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_make_coinbase_tx failed");

    res = kyk_tail_hd_chain(&prev_hd, hd_chain);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_tail_hd_chain failed");

    res = kyk_blk_hash256(pre_blk_hash, prev_hd);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_blk_hash256 failed");

    res = time(NULL);
    check(res != -1, "Failed to kyk_make_coinbase_block: time Failed");
    tts = (uint32_t)res;

    hd = kyk_make_blk_header(tx, tx_count, version, pre_blk_hash, tts, bts);
    check(hd, "Failed to kyk_make_coinbase_block: kyk_make_blk_header failed");

    /* mining */
    kyk_hash_nonce(hd);

    res = kyk_make_block(&blk, hd, tx, tx_count);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_make_block failed");

    *new_blk = blk;

    return 0;
    
error:
    if(tx) kyk_free_tx(tx);
    if(blk) free(blk);
    if(hd) free(hd);
    return -1;
}

/* block used to packing Tx list */
int kyk_make_tx_block(struct kyk_block** new_blk,
		      const struct kyk_blk_hd_chain* hd_chain,
		      const struct kyk_tx* tx,
		      uint64_t mfee,
		      size_t tx_count,
		      const char* note,
		      const uint8_t* pubkey,
		      size_t pub_len)
{
    struct kyk_block* blk = NULL;
    struct kyk_blk_header* prev_hd = NULL;
    struct kyk_blk_header* hd = NULL;
    struct kyk_tx* cb_tx = NULL;
    struct kyk_tx* tx_list = NULL;
    size_t tx_list_size = 0;
    size_t i = 0;

    /* TODO: coinbase Tx out value shoud be adjusted according to the block chain height */
    uint64_t btc_count = KYK_BASE_BTC_COUNAT;
    uint64_t outValue = 0;

    uint8_t pre_blk_hash[32];

    /* timestamp */
    uint32_t tts;

    /* TODO: encoded target should adjust automatically according to the block mean generated time */
    uint32_t bts = KYK_BASE_DIFFT_BITS;

    /* Block version number */
    uint32_t version = KYK_BASE_BLK_VERSION;

    /* Tx count: coinbase block contains only 1 coinbase Tx */
    varint_t cb_tx_count = 1;
    
    int res = -1;


    check(new_blk, "Failed to kyk_make_tx_block: blk is NULL");
    check(hd_chain, "Failed to kyk_make_tx_block: hd_chain is NULL");
    check(tx, "Failed to kyk_make_tx_block: tx is NULL");
    check(note, "Failed to kyk_make_tx_block: note is NULL");

    outValue = ONE_BTC_COIN_VALUE * btc_count;
    outValue += mfee;

    res = kyk_make_coinbase_tx(&cb_tx, note, outValue, pubkey, pub_len);
    check(res == 0, "Failed to kyk_make_tx_block: kyk_make_coinbase_tx failed");

    res = kyk_tail_hd_chain(&prev_hd, hd_chain);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_tail_hd_chain failed");

    res = kyk_blk_hash256(pre_blk_hash, prev_hd);
    check(res == 0, "Failed to kyk_make_tx_block: kyk_blk_hash256 failed");

    res = time(NULL);
    check(res != -1, "Failed to kyk_make_tx_block: time Failed");
    tts = (uint32_t)res;

    /* normal tx count + coinbase tx count */
    tx_list_size = tx_count + cb_tx_count;
    tx_list = calloc(tx_list_size, sizeof(*tx_list));
    check(tx_list, "Failed to kyk_make_tx_block: tx_list calloc failed");

    res = kyk_copy_tx(tx_list, cb_tx);
    check(res == 0, "Failed to kyk_make_tx_block: kyk_copy_tx failed");
    
    for(i = 1; i < tx_list_size; i++){
	res = kyk_copy_tx(tx_list + i, tx + i - 1);
	check(res == 0, "Failed to kyk_make_tx_block: kyk_copy_tx failed");
    }

    hd = kyk_make_blk_header(tx_list, tx_list_size, version, pre_blk_hash, tts, bts);
    check(hd, "Failed to kyk_make_coinbase_block: kyk_make_blk_header failed");

    /* mining */
    kyk_hash_nonce(hd);

    res = kyk_make_block(&blk, hd, tx_list, tx_list_size);
    check(res == 0, "Failed to kyk_make_coinbase_block: kyk_make_block failed");

    *new_blk = blk;

    kyk_free_tx(cb_tx);

    return 0;
    
error:
    if(cb_tx) kyk_free_tx(cb_tx);
    if(tx_list) kyk_free_tx_list(tx_list, tx_list_size);
    return -1;

}

int kyk_tail_hd_chain(struct kyk_blk_header** hd,
		      const struct kyk_blk_hd_chain* hd_chain)
{
    struct kyk_blk_header* hd_cpy = NULL;

    check(hd, "Failed to kyk_tail_hd_chain: hd is NULL");
    check(hd_chain, "Failed to kyk_tail_hd_chain: hd_chain is NULL");
    check(hd_chain -> len >= 1, "Failed to kyk_tail_hd_chain: hd_chain -> len is invalid");

    hd_cpy = hd_chain -> hd_list;

    if(hd_cpy == NULL){
	hd_cpy = NULL;
    } else {
	hd_cpy = hd_cpy + (hd_chain -> len - 1);
    }

    *hd = hd_cpy;

    return 0;

error:

    return -1;
}

int kyk_init_blk_hd_chain(struct kyk_blk_hd_chain** hd_chain)
{
    check(hd_chain, "kyk_init_blk_hd_chain failed: hd_chain is NULL");
    struct kyk_blk_hd_chain* hdc = NULL;
    
    hdc = calloc(1, sizeof(*hdc));
    check(hdc, "Failed to kyk_init_blk_hd_chain: hdc calloc failed");
    
    hdc -> hd_list = NULL;
    hdc -> len = 0;

    *hd_chain = hdc;
    
    return 0;
    
error:
    
    return -1;
}

int kyk_append_blk_hd_chain(struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* hd,
			    size_t count)
{
    struct kyk_blk_header* hd_list = NULL;
    size_t chain_len = 0;
    
    check(hd_chain, "Failed to kyk_append_blk_hd_chain: hd_chain is NULL");
    check(hd, "Failed to kyk_append_blk_hd_chain: hd is NULL");
    check(count > 0, "Failed to kyk_append_blk_hd_chain: invalid count");

    hd_list = hd_chain -> hd_list;
    if(hd_list == NULL && hd_chain -> len > 0){
	log_err("Failed to kyk_append_blk_hd_chain: invalid hd_chain");
	goto error;
    }

    chain_len = hd_chain -> len;

    if(hd_list == NULL){
	hd_list = calloc(count, sizeof(*hd_list));
	check(hd_list, "Failed to kyk_append_blk_hd_chain: hd_list calloc failed");
    } else {
	hd_list = realloc(hd_list, (chain_len + count) * sizeof(*hd_list));
	check(hd_list, "Failed to kyk_append_blk_hd_chain: hd_list relloc failed");
    }

    memcpy(hd_list + chain_len, hd, sizeof(struct kyk_blk_header) * count);

    hd_chain -> hd_list = hd_list;
    hd_chain -> len = chain_len + count;

    return 0;
    
error:

    return -1;
}


void kyk_free_blk_hd_chain(struct kyk_blk_hd_chain* hd_chain)
{
    if(hd_chain){
	if(hd_chain -> hd_list){
	    free(hd_chain -> hd_list);
	    hd_chain -> hd_list = NULL;
	}
	free(hd_chain);
    }
}

void kyk_print_block(const struct kyk_block* blk)
{
    printf("blk -> magic_no: %0x\n", blk -> magic_no);
    printf("blk -> blk_size: %u\n", blk -> blk_size);
    printf("blk -> hd\n");
    kyk_print_blk_header(blk -> hd);
    printf("blk -> tx\n");
    kyk_print_tx_list(blk -> tx, blk -> tx_count);
}

void kyk_print_blk_hd_chain(const struct kyk_blk_hd_chain* hd_chain)
{
    struct kyk_blk_header* hd = NULL;
    size_t i = 0;

    for(i = 0; i < hd_chain -> len; i++){
	hd = hd_chain -> hd_list + i;
	kyk_print_blk_header(hd);
    }
}

void kyk_print_blk_header(const struct kyk_blk_header* hd)
{
    printf("version: %u\n", hd -> version);
    kyk_print_hex("pre_blk_hash ", hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    kyk_print_hex("mrk_root_hash ", hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    printf("tts: %u\n", hd -> tts);
    printf("bts: %0x\n", hd -> bts);
    printf("nonce: %u\n", hd -> nonce);
}


int kyk_compare_hd_chain(const struct kyk_blk_hd_chain* lhd_chain,
			 const struct kyk_blk_hd_chain* rhd_chain,
			 size_t* inx)
{
    struct kyk_blk_header* lhd = NULL;
    struct kyk_blk_header* rhd = NULL;
    size_t i = 0;
    
    check(lhd_chain, "Failed to kyk_compare_hd_chain: lhd_chain is NULL");
    check(rhd_chain, "Failed to kyk_compare_hd_chain: rhd_chain is NULL");
    check(rhd_chain -> hd_list, "Failed to kyk_compare_hd_chain: rhd_chain -> hd_list is NULL");

    if(lhd_chain -> len == 0){
	*inx = 0;
	return 0;
    }

    /* go the tail of lhd_chain */
    lhd = lhd_chain -> hd_list + lhd_chain -> len - 1;

    for(i = 0; i < rhd_chain -> len; i++){
	rhd = rhd_chain -> hd_list + i;
	if(kyk_eq_blk_hd(lhd, rhd)){
	    *inx = i + 1;
	    break;
	}
    }


    return 0;

error:

    return -1;
}

int kyk_eq_blk_hd(const struct kyk_blk_header* lhd, const struct kyk_blk_header* rhd)
{
    int pre_blk_hash_eq = 0;
    int mrk_root_hash_eq = 0;
    
    pre_blk_hash_eq = kyk_digest_eq(lhd -> pre_blk_hash, rhd -> pre_blk_hash, sizeof(lhd -> pre_blk_hash));
    mrk_root_hash_eq = kyk_digest_eq(lhd -> mrk_root_hash, rhd -> mrk_root_hash, sizeof(lhd -> mrk_root_hash));

    if(pre_blk_hash_eq && mrk_root_hash_eq){
	return 1;
    } else {
	return 0;
    }
}
