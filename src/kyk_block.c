#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_tx.h"
#include "kyk_block.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_buff.h"
#include "dbg.h"


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
    if(blk -> hd) free(blk -> hd);
    if(blk -> tx) kyk_free_tx(blk -> tx);
    if(blk) free(blk);
}

int kyk_unpack_blk_header(const struct kyk_buff *buf, struct kyk_blk_header *hd)
{
    uint8_t* bufp = buf -> base;
    bufp += buf -> idx;

    beej_unpack((unsigned char*)bufp, "<L", &hd -> version);
    bufp += sizeof(hd -> version);

    kyk_reverse_pack_chars(hd -> pre_blk_hash, (unsigned char*)bufp, sizeof(hd -> pre_blk_hash));
    bufp += sizeof(hd -> pre_blk_hash);

    kyk_reverse_pack_chars(hd -> mrk_root_hash, (unsigned char*)bufp, sizeof(hd -> mrk_root_hash));
    bufp += sizeof(hd -> mrk_root_hash);

    beej_unpack((unsigned char*)bufp, "<L", &hd -> tts);
    bufp += sizeof(hd -> tts);

    beej_unpack((unsigned char*)bufp, "<L", &hd -> bts);
    bufp += sizeof(hd -> bts);

    beej_unpack((unsigned char*)bufp, "<L", &hd -> nonce);

    return 1;
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

    hd -> tts = tts;
    hd -> bts = bts;

    return hd;

error:
    return NULL;
}


int kyk_make_block(struct kyk_block* blk,
		   struct kyk_blk_header* blk_hd,
		   struct kyk_tx* tx_list)
{
    return 0;
}

