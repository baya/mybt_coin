#ifndef KYK_BLOCK_H__
#define KYK_BLOCK_H__

#include "varint.h"
#include "kyk_tx.h"
#include "kyk_ldb.h"
#include "kyk_buff.h"

#define KYK_BLK_HD_LEN 80
#define KYK_BLK_HD_NO_NONCE_LEN 76


struct kyk_blk_header {
    uint32_t version;
    uint8_t pre_blk_hash[32];
    uint8_t mrk_root_hash[32];
    uint32_t tts;
    uint32_t bts;
    uint32_t nonce;
    uint8_t blk_hash[32];
};

struct kyk_block {
    uint32_t magic_no;
    uint32_t blk_size;
    struct kyk_blk_header *hd;
    varint_t tx_count;
    struct kyk_tx *tx;
};

size_t kyk_seri_blk_hd(uint8_t *buf, const struct kyk_blk_header *hd);
size_t kyk_seri_blk_hd_without_nonce(uint8_t *buf, const struct kyk_blk_header *hd);
void kyk_free_block(struct kyk_block *blk);
int kyk_unpack_blk_header(const struct kyk_buff *buf, struct kyk_blk_header *hd);
size_t kyk_ser_blk(struct kyk_buff* buf, const struct kyk_block* blk);
size_t kyk_ser_blk_for_file(struct kyk_buff* buf, const struct kyk_block* blk);

#endif
