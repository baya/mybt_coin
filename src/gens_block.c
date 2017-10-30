#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>


#include "kyk_block.h"
#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_address.h"
#include "kyk_mkl_tree.h"
#include "kyk_ser.h"
#include "kyk_difficulty.h"
#include "kyk_hash_nonce.h"
#include "kyk_pem.h"

#define GENS_COINBASE "From 4/Sept/2017 China start suppressing the Bitcoin"
#define GENS_PEM "data/kyk-gens-priv.pem"
#define SC_PUBKEY_LEN 1000
#define TX_BUF_LEN 2000
#define BLK_LEN 1000 * 1000
#define BLK_HD_LEN 80
#define TX_COUNT 1
#define BLK_MAGIC_NO 0xD9B4BEF9

void create_gens_tx(struct kyk_tx *gens_tx);
void make_coinbase(struct kyk_txin *txin, const char *cb_note);
struct kyk_mkltree_level *make_mkl_tree_root(struct kyk_tx_buf *buf_list, size_t len);

struct kyk_block* make_gens_block()
{
    struct kyk_block *blk = malloc(sizeof(struct kyk_block));
    struct kyk_tx tx0;
    uint8_t tx_buf[TX_BUF_LEN];
    /* uint8_t hd_buf[BLK_HD_LEN]; */
    /* uint8_t blk_buf[BLK_LEN]; */
    /* uint8_t *blk_bfp = blk_buf; */
    size_t tx_len;
    size_t wsize;
    size_t hd_len;
    size_t blk_len = 0;
    struct kyk_blk_header blk_hd;
    struct kyk_tx_buf tx_buf_list[TX_COUNT];
    struct kyk_tx_buf *tx_buf_ptr = tx_buf_list;
    struct kyk_mkltree_level *mkl_root;
    /* char *err_msg = "failed to make gens block"; */
    /* FILE *fp = fopen("tmp/kyk-gens-block.dat", "wb"); */
    /* check(fp != NULL, "failed to open kyk-gens-block.dat file"); */
    
    create_gens_tx(&tx0);
    tx_len = kyk_seri_tx(tx_buf, &tx0);
    tx_buf_ptr -> bdy = tx_buf;
    tx_buf_ptr -> len = tx_len;

    blk_hd.version = 1;
    kyk_parse_hex(blk_hd.pre_blk_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    mkl_root = make_mkl_tree_root(tx_buf_ptr, TX_COUNT);
    kyk_cpy_mkl_root_value(blk_hd.mrk_root_hash, mkl_root);
    blk_hd.tts = 1504483200;
    /* bts 越大，难度越低 */
    //blk_hd.bts = 0x1e00ffff;
    blk_hd.bts = 0x1f00ffff;
    blk_hd.nonce = 0;

    kyk_hsh_nonce(&blk_hd);

    blk -> hd = &blk_hd;
    blk -> tx = &tx0;

    /* hd_len = kyk_seri_blk_hd(hd_buf, &blk_hd); */
    /* blk_len += kyk_inc_ser(&blk_bfp, "raw-buf", hd_buf, hd_len); */
    /* blk_len += kyk_inc_ser(&blk_bfp, "tx-count", TX_COUNT); */
    /* blk_len += kyk_inc_ser(&blk_bfp, "raw-buf", tx_buf, tx_len); */


    /* wsize = fwrite(blk_buf, sizeof(blk_buf[0]), blk_len, fp); */
    /* check(wsize == blk_len, "failed to save gens block to tmp/kyk-gens-block.dat"); */

    /* uint8_t target_blk_hash[32]; */
    /* kyk_parse_hex(target_blk_hash, "0000876c9ef8c1f8b2a3012ec1bdea7296f95ae21681799f8adf967f548bf8f3"); */
    /* check(kyk_digest_eq(blk_hd.blk_hash, target_blk_hash, sizeof(target_blk_hash)), "failed to get the correct block hash"); */

    /* uint8_t target_mkl_rt[32]; */
    /* kyk_parse_hex(target_mkl_rt, "b76d27da4abf50387dd70f5d6cc7e4df1d54722631cbbfdd292463df77aa0dbd"); */
    /* check(kyk_digest_eq(blk_hd.mrk_root_hash, target_mkl_rt, sizeof(target_mkl_rt)), "failed to get the correct merkle root"); */

    /* fclose(fp); */

    return blk;

error:
    /* if(fp) fclose(fp); */
    return NULL;
}

struct kyk_mkltree_level *make_mkl_tree_root(struct kyk_tx_buf *buf_list, size_t len)
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
    txin -> pre_tx_inx = 0xffffffff;
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

