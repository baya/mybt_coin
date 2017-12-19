#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#include "kyk_validate.h"
#include "kyk_utils.h"
#include "kyk_block.h"
#include "kyk_tx.h"
#include "kyk_difficulty.h"
#include "kyk_mkl_tree.h"
#include "kyk_script.h"
#include "dbg.h"

static int validate_hd_bts(const struct kyk_blk_header* hd);
static int validate_hd_mkl_root(const struct kyk_blk_header* hd,
				const struct kyk_tx* tx_list,
				varint_t tx_count);


int kyk_validate_block(const struct kyk_blk_hd_chain* hd_chain,
		       const struct kyk_block* blk)
{
    int res = -1;

    check(hd_chain, "Failed to kyk_validate_block: hd_chain is NULL");
    check(blk, "Failed to kyk_validte_block: blk is NULL");
    check(blk -> hd, "Failed to kyk_validate_block: blk -> hd is NULL");

    res = kyk_validate_blk_header(hd_chain, blk -> hd);
    check(res == 0, "Failed to kyk_validate_block: kyk_validate_blk_header failed");

    res = validate_hd_mkl_root(blk -> hd, blk -> tx, blk -> tx_count);
    check(res == 0, "Failed to kyk_validate_block: validate_hd_mkl_root failed");
    
    return 0;

error:

    return -1;
}


int kyk_validate_blk_header(const struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* outHd)
{
    check(hd_chain, "Failed to validate_blk_header: hd_chain is NULL");
    check(outHd, "Failed to validate_blk_header: hd is NULL");
    check(outHd -> pre_blk_hash, "Failed to validate_blk_header: pre_blk_hash is NULL");
    struct kyk_blk_header* prev_hd = NULL;
    uint8_t digest[32];
    int res = -1;

    check(hd_chain, "Failed to kyk_validate_blk_header: hd_chain is NULL");
    check(outHd, "Failed to kyk_validate_blk_header: outHd is NULL");


    if(hd_chain -> len == 0){
	return 0;
    }

    prev_hd = hd_chain -> hd_list + hd_chain -> len - 1;
    check(prev_hd, "Failed to kyk_validate_blk_header: prev_hd is NULL");
    
    res = kyk_blk_hash256(digest, prev_hd);
    check(res == 0, "Failed to kyk_validate_blk_header: kyk_blk_hash256 failed");
    check(kyk_digest_eq(outHd -> pre_blk_hash, digest, sizeof(digest)), "Failed to kyk_validate_blk_header: invalid pre_blk_hash");

    res = validate_hd_bts(outHd);
    check(res == 0, "Failed to kyk_validate_blk_header: validate_hd_bts failed");

    return 0;

error:

    return -1;
}

int validate_hd_bts(const struct kyk_blk_header* hd)
{
    mpz_t tg, hs;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int res = -1;

    mpz_init(tg);
    mpz_set_ui(tg, 0);

    mpz_init(hs);
    mpz_set_ui(hs, 0);

    /* bts to target */
    kyk_bts2target(hd -> bts, tg);

    res = kyk_blk_hash256(digest, hd);
    check(res == 0, "Failed to validate_hd_bts: kyk_blk_hash256 failed");

    mpz_import(hs, sizeof(digest), 1, 1, 1, 0, digest);
    check(mpz_cmp(hs, tg) <= 0, "Failed to validate_hd_bts: block hash dosen't reach target");

    return 0;
    
error:

    return -1;

}

int validate_hd_mkl_root(const struct kyk_blk_header* hd,
			 const struct kyk_tx* tx_list,
			 varint_t tx_count)
{
    struct kyk_mkltree_level* mkl_root = NULL;
    uint8_t digest[MKL_NODE_BODY_LEN];
    int res = -1;

    check(hd, "Failed to validate_hd_mkl_root: hd is NULL");
    check(tx_list, "Failed to validate_hd_mkl_root: tx_list is NULL");
    check(tx_count >= 1, "Failed to validate_hd_mkl_root: tx_count is invalid");

    mkl_root = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_root, "Failed to validate_hd_mkl_root: kyk_make_mkl_tree_root_from_tx_list failed");

    kyk_cpy_mkl_root_value(digest, mkl_root);

    res = kyk_digest_eq(hd -> mrk_root_hash, digest, sizeof(digest));
    check(res == 1, "Failed to validate_hd_mkl_root: hd -> mrk_root_hash is invalide");

    kyk_free_mkl_tree(mkl_root);
    
    return 0;
    
error:
    if(mkl_root) kyk_free_mkl_tree(mkl_root);
    return -1;
}


int kyk_validate_txin_script_sig(const struct kyk_txin* txin,
				 const uint8_t* unsig_buf,
				 size_t unsig_buf_len,
				 const struct kyk_tx* prev_tx)
{
    struct kyk_txout* txout = NULL;
    uint8_t prev_txid[32];
    uint8_t* sc_buf = NULL;
    size_t sc_buf_len = 0;
    int res = -1;
    int verified = 0;
    
    check(txin, "Failed to kyk_validate_txin_script_sig: txin is NULL");
    check(unsig_buf, "Failed to kyk_validate_txin_script_sig: unsig_buf is NULL");
    check(prev_tx, "Failed to kyk_validate_txin_script_sig: prev_tx is NULL");
    check(prev_tx -> txout, "Failed to kyk_validate_txin_script_sig: prve_tx -> txout is NULL");

    res = kyk_tx_hash256(prev_txid, prev_tx);
    check(res == 0, "Failed to kyk_validate_txin_script_sig: kyk_tx_hash256 failed");
    
    res = kyk_digest_eq(txin -> pre_txid, prev_txid, sizeof(prev_txid));
    check(res == 1, "Failed to kyk_validate_txin_script_sig: txin -> pre_txid is invalid");

    txout = prev_tx -> txout;
    txout += txin -> pre_txout_inx;

    res = kyk_combine_txin_txout_for_script(&sc_buf, &sc_buf_len, txin, txout);
    check(res == 0, "Failed to kyk_validate_txin_script_sig: kyk_combine_txin_txout_for_script failed");

    verified = kyk_run_script(sc_buf, sc_buf_len, unsig_buf, unsig_buf_len);
    check(verified == 1, "Failed to kyk_validate_txin_script_sig: kyk_run_script failed");

    return 0;

error:

    return -1;
}

