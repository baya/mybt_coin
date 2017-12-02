#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_tx.h"
#include "kyk_block.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_buff.h"
#include "kyk_mkl_tree.h"
#include "kyk_sha.h"
#include "dbg.h"


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

/* buf should not have Magic No and Blocksize */
int kyk_deseri_block(struct kyk_block* blk,
		     const uint8_t* buf,
		     size_t* byte_num)
{
    const uint8_t* bufp = NULL;
    int res = -1;
    size_t len = 0;
    int arg_checked = 0;

    check(blk, "Failed to kyk_deseri_block: blk is NULL");
    /* we need a clean block with blank block header */
    check(blk -> hd == NULL, "Failed to kyk_deseri_block: blk -> hd is not NULL");
    /* we need a clean block with blank tx list */
    check(blk -> tx == NULL, "Failed to kyk_deseri_block: blk -> tx is not NULL");
    check(buf, "Failed to kyk_deseri_block: buf is NULL");

    bufp = buf;

    blk -> hd = calloc(1, sizeof(*blk -> hd));
    check(blk -> hd, "Failed to kyk_parse_block: blk -> hd calloc failed");

    res = kyk_deseri_blk_header(blk -> hd, buf, &len);
    check(res == 0, "Failed to kyk_parse_block: kyk_deseri_blk_header failed");
    bufp += len;

    len = kyk_unpack_varint(bufp, &blk -> tx_count);
    check(len > 0, "Failed to kyk_deseri_block: kyk_unpack_varint failed");
    check(blk -> tx_count > 0, "Failed to kyk_deseri_block: blk -> tx_count is invalid");
    bufp += len;

    blk -> tx = calloc(blk -> tx_count, sizeof(*blk -> tx));
    check(blk -> tx, "Failed to kyk_deseri_block: blk -> tx calloc failed");

    res = kyk_deseri_tx_list(blk -> tx, blk -> tx_count, bufp, &len);
    check(res == 0, "Failed to kyk_deseri_block: kyk_deseri_tx_list failed");
    bufp += len;

    *byte_num = bufp - buf;
    
    return 0;

error:

    if(arg_checked){
	if(blk -> hd) {
	    free(blk -> hd);
	    blk -> hd = NULL;
	}
	if(blk -> tx) {
	    kyk_free_tx(blk -> tx);
	    blk -> tx = NULL;
	}
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


size_t kyk_ser_blk(struct kyk_buff* buf, const struct kyk_block* blk)
{
    size_t len = 0;
    size_t i = 0;
    size_t start_idx = buf -> idx;
    struct kyk_blk_header* hd = blk -> hd;
    struct kyk_tx* tx = blk -> tx;
    uint8_t *base = buf -> base;
    
    len = kyk_seri_blk_hd(base + buf -> idx, hd);
    buf -> idx += len;
    buf -> len += len;

    len = kyk_pack_varint(base + buf -> idx, blk -> tx_count);
    buf -> idx += len;
    buf -> len += len;

    for(i = 0; i < blk -> tx_count; i++){
	len = kyk_seri_tx(base + buf -> idx, tx + i);
	buf -> idx += len;
	buf -> len += len;
    }

    return(buf -> idx - start_idx);
}

size_t kyk_ser_blk_for_file(struct kyk_buff* buf, const struct kyk_block* blk)
{
    size_t len = 0;
    size_t start_idx = buf -> idx;
    uint8_t *base = buf -> base;

    len = beej_pack(base + buf -> idx, "<L", blk -> magic_no);
    buf -> idx += len;
    buf -> len += len;

    len = beej_pack(base + buf -> idx, "<L", blk -> blk_size);
    buf -> idx += len;
    buf -> len += len;

    len = kyk_ser_blk(buf, blk); 
    check(len == blk -> blk_size, "faile to serialize block");

    return(buf -> idx - start_idx);

error:
    return 0;
}

/* we don't pass nonce here, because noce is computed by mining */
struct kyk_blk_header* kyk_make_blk_header(struct kyk_tx* tx_list,
					   size_t tx_count,
					   uint32_t version,
					   uint8_t* pre_blk_hash,
					   uint32_t tts,
					   uint32_t bts)
{
    struct kyk_blk_header* hd = NULL;
    struct kyk_mkltree_level* mkl_root = NULL;

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


int kyk_make_block(struct kyk_block* blk,
		   struct kyk_blk_header* blk_hd,
		   struct kyk_tx* tx_list,
		   varint_t tx_count
    )
{
    check(blk, "Failed to kyk_make_block: blk is NULL");
    check(blk_hd, "Failed to kyk_make_block: blk_hd is NULL");
    check(tx_list, "Failed to kyk_make_block: tx_list is NULL");

    struct kyk_tx* tx = NULL;
    size_t tx_size = 0;
    int i = 0;
    int res = -1;

    blk -> blk_size = 0;
    blk -> hd = blk_hd;
    blk -> blk_size += KYK_BLK_HD_LEN;
    blk -> tx_count = tx_count;
    blk -> blk_size += get_varint_size(blk -> tx_count);
    blk -> tx = tx_list;

    for(i = 0; (varint_t)i < tx_count; i++){
	tx = tx_list + i;
	res = kyk_get_tx_size(tx, &tx_size);
	check(res == 0, "Failed to kyk_make_block: kyk_get_tx_size failed");
	blk -> blk_size += tx_size;
    }
    
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

int kyk_validate_blk_header(struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* outHd)
{
    check(hd_chain, "Failed to validate_blk_header: hd_chain is NULL");
    check(outHd, "Failed to validate_blk_header: hd is NULL");
    check(outHd -> pre_blk_hash, "Failed to validate_blk_header: pre_blk_hash is NULL");
    
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_blk_header* prev_hd = NULL;
    uint8_t digest[32];
    int res = -1;

    hdc = hd_chain;

    if(hdc -> len == 0){
	return 0;
    }

    prev_hd = hdc -> hd_list + hd_chain -> len;
    check(prev_hd, "Failed to kyk_validate_blk_header: prev_hd is NULL");
    
    res = kyk_blk_hash256(digest, prev_hd);
    check(res == 0, "Failed to kyk_validate_blk_header: kyk_blk_hash256 failed");

    check(kyk_digest_eq(outHd -> pre_blk_hash, digest, sizeof(digest)), "Failed to kyk_validate_blk_header: invalid pre_blk_hash");

    return 0;

error:

    return -1;
}

