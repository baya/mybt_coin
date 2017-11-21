#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>


#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_address.h"
#include "kyk_pem.h"
#include "kyk_buff.h"
#include "kyk_ecdsa.h"
#include "mu_unit.h"

#define SC_PUBKEY_LEN 1000
#define KYK_TX_BUF_LEN 10000
#define TXID_LEN 32

void make_coinbase(struct kyk_txin *txin, const char *cb_note);

char *test_make_gens_tx()
{

    uint8_t tx_buf[KYK_TX_BUF_LEN];
    size_t tx_buf_len;
    
    struct kyk_tx tx0;
    struct kyk_txin *txin;
    struct kyk_txout *txout;

    char *cb = "From 4/Sept/2017 China start suppressing the Bitcoin";
    
    uint8_t priv[32];
    char *pem_name = "data/kyk-gens-priv.pem";
    char *addr = NULL;
    uint8_t sc_pbk[SC_PUBKEY_LEN];
    size_t sc_pbk_len;

    FILE *fp = fopen("tmp/gens-tx.dat", "wb");
    size_t wsize;

    struct kyk_digst *txid = NULL;
    char *err_msg = "Failed to test make gens tx";

    uint8_t target_txid[TXID_LEN];

    kyk_parse_hex(target_txid, "b76d27da4abf50387dd70f5d6cc7e4df1d54722631cbbfdd292463df77aa0dbd");

    tx0.version = 1;
    tx0.vin_sz = 1;
    tx0.lock_time = 0;
    tx0.txin = malloc(tx0.vin_sz * sizeof(struct kyk_txin));
    tx0.vout_sz = 1;
    tx0.txout = malloc(tx0.vout_sz * sizeof(struct kyk_txout));
    txin = tx0.txin;
    txout = tx0.txout;

    memset(txin -> pre_txid, 0x00, sizeof(txin -> pre_txid));
    txin -> pre_tx_inx = 0xffffffff;
    make_coinbase(txin, cb);
    
    txin -> seq_no = 0xFFFFFFFF;

    txout -> value = 10000000000;
    

    int res = 0;
    res = get_priv_from_pem(priv, pem_name);
    check(res > 0, "Failed to get private key from pem file");
    addr = kyk_make_address(priv, sizeof(priv));
    sc_pbk_len = p2pkh_sc_from_address(sc_pbk, addr);
    txout -> sc_size = sc_pbk_len;
    txout -> sc = sc_pbk;

    tx_buf_len = kyk_seri_tx(tx_buf, &tx0);

    wsize = fwrite(tx_buf, sizeof(tx_buf[0]), tx_buf_len, fp);
    check(wsize == tx_buf_len, "failed to save gens tx to tmp/gens-tx.dat");

    txid = kyk_inver_hash((char *)tx_buf, tx_buf_len);

    mu_assert(kyk_digest_eq(txid -> body, target_txid, TXID_LEN), "Failed to make the correct Genesis Tx");
    free(txid);

    return NULL;
error:
    if(addr) free(addr);
    if(txid) kyk_free_digst(txid);
    return err_msg;
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

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_gens_tx);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
