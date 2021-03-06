#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "gens_block.h"
#include "kyk_tx.h"
#include "kyk_buff.h"
#include "dbg.h"

#define GENS_COINBASE "From 4/Sept/2017 China start suppressing the Bitcoin"
#define GENS_PEM "data/kyk-gens-priv.pem"
#define SC_PUBKEY_LEN 1000
#define TX_BUF_LEN 2000
#define TX_COUNT 1

void create_gens_tx(struct kyk_tx *gens_tx);
void make_coinbase(struct kyk_txin *txin, const char *cb_note);
struct kyk_mkltree_level *make_mkl_tree_root(struct kyk_bon_buff *buf_list, size_t len);

struct kyk_block* make_gens_block()
{
    struct kyk_block *blk = malloc(sizeof(struct kyk_block));
    struct kyk_tx *tx0;
    uint8_t tx_buf[TX_BUF_LEN];
    size_t tx_len = 0;
    struct kyk_blk_header* blk_hd;
    struct kyk_bon_buff tx_buf_list[TX_COUNT];
    struct kyk_bon_buff *tx_buf_ptr = tx_buf_list;
    struct kyk_mkltree_level *mkl_root;
    size_t blk_size = 0;
    int res = -1;

    res = kyk_init_block(blk);
    check(res == 0, "Failed to make_gens_block: kyk_init_block failed");

    blk -> tx_count = TX_COUNT;
    blk_size += get_varint_size(blk -> tx_count);
    tx0 = blk -> tx;
    blk_hd = blk -> hd;
    
    create_gens_tx(tx0);
    tx_len = kyk_seri_tx(tx_buf, tx0);
    tx_buf_ptr -> base = tx_buf;
    tx_buf_ptr -> len = tx_len;
    blk_size += tx_len;

    blk_hd -> version = 1;
    kyk_parse_hex(blk_hd -> pre_blk_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    mkl_root = make_mkl_tree_root(tx_buf_ptr, blk -> tx_count);
    kyk_cpy_mkl_root_value(blk_hd -> mrk_root_hash, mkl_root);
    blk_hd -> tts = 1504483200;
    /* bts 越大，难度越低 */
    //blk_hd.bts = 0x1e00ffff;
    blk_hd -> bts = 0x1f00ffff;
    blk_hd -> nonce = 0;
    blk_size += KYK_BLK_HD_LEN;

    kyk_hash_nonce(blk_hd);
    blk -> magic_no = KYK_BLK_MAGIC_NO;
    blk -> blk_size = blk_size;

    return blk;

error:

    return NULL;

}

struct kyk_mkltree_level *make_mkl_tree_root(struct kyk_bon_buff *buf_list, size_t len)
{
    struct kyk_mkltree_level *leaf_level;
    struct kyk_mkltree_level *root_level;

    leaf_level = create_mkl_leafs(buf_list, len);
    root_level = create_mkl_tree(leaf_level);

    return root_level;
}


void create_gens_tx(struct kyk_tx *gens_tx)
{
    struct kyk_txin *txin;
    struct kyk_txout *txout;
    char *addr;
    uint8_t sc_pbk[SC_PUBKEY_LEN];

    gens_tx -> version = 1;
    gens_tx -> vin_sz = 1;
    gens_tx -> lock_time = 0;
    gens_tx -> txin = malloc(gens_tx -> vin_sz * sizeof(struct kyk_txin));
    gens_tx -> vout_sz = 1;
    gens_tx -> txout = malloc(gens_tx -> vout_sz * sizeof(struct kyk_txout));
    txin = gens_tx -> txin;
    txout = gens_tx -> txout;

    memset(txin -> pre_txid, 0x00, sizeof(txin -> pre_txid));
    txin -> pre_txout_inx = COINBASE_INX;
    make_coinbase(txin, GENS_COINBASE);
    
    txin -> seq_no = 0xFFFFFFFF;
    txout -> value = 10000000000;

    addr = make_address_from_pem(GENS_PEM);

    txout -> sc_size = p2pkh_sc_from_address(sc_pbk, addr);
    txout -> sc = malloc(txout -> sc_size * sizeof(uint8_t));
    memcpy(txout -> sc, sc_pbk, txout -> sc_size);

}


void make_coinbase(struct kyk_txin *txin, const char *cb_note)
{
    unsigned char cb_tmp[1000] = {0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04};
    size_t cb_len = 7;
    size_t cb_note_len = strlen(cb_note);

    cb_tmp[7] = (uint8_t) cb_note_len;
    cb_len += 1;

    memcpy(cb_tmp + 8, cb_note, cb_note_len);
    cb_len += cb_note_len;

    txin -> sc_size = cb_len;

    txin -> sc = malloc(txin -> sc_size * sizeof(unsigned char));
    memcpy(txin -> sc, cb_tmp, txin -> sc_size);
}

