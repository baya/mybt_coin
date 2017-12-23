#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_data.h"
#include "kyk_buff.h"
#include "kyk_tx.h"
#include "kyk_utils.h"
#include "mu_unit.h"

/* This target test data source is from: https://webbtc.com/tx/b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082.json */
/* Txid is b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082 */
static uint8_t TARGET_TX1_BUF[134] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x07, 0x04, 0xff, 0xff, 0x00, 0x1d, 0x01,
    0x02, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0xf2,
    0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x43, 0x41,
    0x04, 0xd4, 0x6c, 0x49, 0x68, 0xbd, 0xe0, 0x28,
    0x99, 0xd2, 0xaa, 0x09, 0x63, 0x36, 0x7c, 0x7a,
    0x6c, 0xe3, 0x4e, 0xec, 0x33, 0x2b, 0x32, 0xe4,
    0x2e, 0x5f, 0x34, 0x07, 0xe0, 0x52, 0xd6, 0x4a,
    0xc6, 0x25, 0xda, 0x6f, 0x07, 0x18, 0xe7, 0xb3,
    0x02, 0x14, 0x04, 0x34, 0xbd, 0x72, 0x57, 0x06,
    0x95, 0x7c, 0x09, 0x2d, 0xb5, 0x38, 0x05, 0xb8,
    0x21, 0xa8, 0x5b, 0x23, 0xa7, 0xac, 0x61, 0x72,
    0x5b, 0xac, 0x00, 0x00, 0x00, 0x00
};

int build_testing_tx1(struct kyk_tx** out_tx);

char* test_get_tx_size()
{
    struct kyk_tx* tx;
    size_t tx_size = 0;
    size_t target_size = 134;
    int res = -1;

    res = build_testing_tx1(&tx);
    mu_assert(res == 0, "Failed to test_get_tx_size: build_testing_tx1 failed");

    kyk_get_tx_size(tx, &tx_size);
    mu_assert(tx_size == target_size, "Failed to test_get_tx_size: get tx size failed");
    
    return NULL;
}

char* test_create_tx()
{
    struct kyk_tx* tx = NULL;
    tx = kyk_create_tx(1, 1, 1, 0);
    mu_assert(tx -> version == 1, "Failed to test_create_tx");

    return NULL;
}

char* test_seri_tx()
{

    struct kyk_tx* tx = NULL;
    int res = -1;
    uint8_t buf[200];
    size_t len = 0;

    res = build_testing_tx1(&tx);
    mu_assert(res == 0, "Failed to test_seri_tx: build_testing_tx1 failed");

    len = kyk_seri_tx(buf, tx);
    mu_assert(len == sizeof(TARGET_TX1_BUF), "Failed to test_seri_tx");
    mu_assert(kyk_digest_eq(buf, TARGET_TX1_BUF, len), "Failed to test_seri_tx");
    
    return NULL;

}

char* test_deseri_tx()
{
    uint8_t target_txid[] = {
	0xb1, 0xfe, 0xa5, 0x24, 0x86, 0xce, 0x0c, 0x62,
	0xbb, 0x44, 0x2b, 0x53, 0x0a, 0x3f, 0x01, 0x32,
	0xb8, 0x26, 0xc7, 0x4e, 0x47, 0x3d, 0x1f, 0x2c,
	0x22, 0x0b, 0xfa, 0x78, 0x11, 0x1c, 0x50, 0x82
    };
    uint8_t digest[32];
    int res = -1;
    size_t len = 0;
    struct kyk_tx* tx = NULL;
    
    tx = malloc(sizeof(*tx));
    check(tx, "Failed to test_deseri_tx: tx malloc failed");

    res = kyk_deseri_tx(tx, TARGET_TX1_BUF, &len);
    mu_assert(res == 0, "Failed to test_deseri_tx");

    res = kyk_tx_hash256(digest, tx);
    check(res == 0, "Failed to test_deseri_tx: kyk_tx_hash256 failed");
    mu_assert(kyk_digest_eq(digest, target_txid, sizeof(digest)), "Failed to test_deseri_tx");
    
    return NULL;

error:

    return "Failed to test_deseri_tx";
}

char* test_deseri_new_tx()
{
    struct kyk_tx* tx = NULL;
    uint8_t expect_txid[] = {
	0x0c, 0x50, 0x1c, 0x58, 0xc0, 0xa2, 0xce, 0x4f, 0x3a, 0x88, 0xf3, 0x2a, 0x28, 0xab, 0x2c, 0xad,
	0xea, 0x88, 0x43, 0xc2, 0xca, 0x90, 0x59, 0x70, 0xf6, 0x47, 0x16, 0x9b, 0x88, 0xbc, 0x51, 0xcf	
    };
    uint8_t txid[32];
    int res = -1;
 
    res = kyk_deseri_new_tx(&tx, VIN4_TX, NULL);
    mu_assert(res == 0, "Failed to test_deseri_new_tx");

    res = kyk_tx_hash256(txid, tx);
    mu_assert(kyk_digest_eq(txid, expect_txid, sizeof(txid)), "Failed to test_deseri_new_tx");

    return NULL;
    
}

char* test_deseri_tx_list()
{
    uint8_t target_txid[] = {
	0xb1, 0xfe, 0xa5, 0x24, 0x86, 0xce, 0x0c, 0x62,
	0xbb, 0x44, 0x2b, 0x53, 0x0a, 0x3f, 0x01, 0x32,
	0xb8, 0x26, 0xc7, 0x4e, 0x47, 0x3d, 0x1f, 0x2c,
	0x22, 0x0b, 0xfa, 0x78, 0x11, 0x1c, 0x50, 0x82
    };
    uint8_t digest[32];
    int res = -1;
    size_t len = 0;
    size_t tx_count = 1;
    struct kyk_tx* tx_list = NULL;
    
    tx_list = malloc(tx_count * sizeof(*tx_list));
    check(tx_list, "Failed to test_deseri_tx: tx_list malloc failed");

    res = kyk_deseri_tx_list(tx_list, tx_count, TARGET_TX1_BUF, &len);
    mu_assert(res == 0, "Failed to test_deseri_tx_list");

    res = kyk_tx_hash256(digest, tx_list);
    check(res == 0, "Failed to test_deseri_tx_list: kyk_tx_hash256 failed");
    mu_assert(kyk_digest_eq(digest, target_txid, sizeof(digest)), "Failed to test_deseri_tx_list");
    
    return NULL;

error:

    return "Failed to test_deseri_tx";
}


char* test_seri_tx_list()
{
    struct kyk_tx* tx = NULL;
    struct kyk_bon_buff* buf_list = NULL;
    struct kyk_bon_buff* bufp = NULL;
    size_t tx_count = 1;
    int res = -1;

    buf_list = calloc(tx_count, sizeof(*buf_list));
    bufp = buf_list;
    res = build_testing_tx1(&tx);
    mu_assert(res == 0, "Failed to test_seri_tx_list: build_testing_tx1 failed");

    res = kyk_seri_tx_list(buf_list, tx, tx_count);
    mu_assert(res == 0, "Failed to test_seri_tx_list: kyk_seri_tx_list failed");
    
    mu_assert(kyk_digest_eq(bufp -> base, TARGET_TX1_BUF, bufp -> len), "Failed to test_seri_tx_list");

    return NULL;
}


char* test2_seri_tx_list()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx_list = NULL;
    struct kyk_bon_buff* buf_list = NULL;
    struct kyk_bon_buff* bufp = NULL;
    size_t tx_count = 2;
    int res = -1;
    char *errmsg = "failed to test2_seri_tx_list";

    tx_list = calloc(tx_count, sizeof(struct kyk_tx));
    check(tx_list, "Failed to calloc tx_list");
    
    buf_list = calloc(tx_count, sizeof(*buf_list));
    check(buf_list, "Failed to calloc buf_list");
    
    bufp = buf_list;
    res = build_testing_tx1(&tx);
    mu_assert(res == 0, "Failed to test_seri_tx_list: build_testing_tx1 failed");
    res = kyk_copy_tx(tx_list, tx);
    check(res == 0, "Failed to kyk_copy_tx");
    
    res = kyk_copy_tx(tx_list+1, tx);
    check(res == 0, "Failed to kyk_copy_tx");

    res = kyk_seri_tx_list(buf_list, tx_list, tx_count);
    
    mu_assert(res == 0, "Failed to test_seri_tx_list: kyk_seri_tx_list failed");
    mu_assert(kyk_digest_eq(bufp -> base, TARGET_TX1_BUF, bufp -> len), "Failed to test_seri_tx_list");
    bufp++;
    mu_assert(kyk_digest_eq(bufp -> base, TARGET_TX1_BUF, bufp -> len), "Failed to test_seri_tx_list");

    return NULL;

error:

    return errmsg;
}


char* test_make_coinbase_tx()
{
    struct kyk_tx* tx = NULL;
    char* note = "this is a coinbase tx";
    uint64_t outValue = 10000000000;
    uint8_t pubkey[33] = {
	0x03, 0xd3, 0xcf, 0xed, 0xe5, 0x6a, 0x79, 0xf6,
	0xb6, 0x90, 0x7a, 0x5f, 0x14, 0x5a, 0x76, 0xcc,
	0x5c, 0xd7, 0x54, 0x9b, 0x24, 0x4f, 0x7d, 0x93,
	0xbb, 0x72, 0xd4, 0xf9, 0xe4, 0x61, 0xb1, 0x46,
	0xa9	
    };
    int res = -1;

    res = kyk_make_coinbase_tx(&tx, note, outValue, pubkey, sizeof(pubkey));
    mu_assert(res == 0, "Failed to kyk_make_coinbase_tx");
    mu_assert(tx -> version == 1, "Failed to test_make_coinbase_tx");

    kyk_free_tx(tx);
    
    return NULL;
}


char* test_kyk_get_addr_from_txout()
{
    struct kyk_tx* tx = NULL;
    struct kyk_txout* txout = NULL;
    size_t check_num = 0;
    char* btc_addr = NULL;
    const char* expect_addr = "1LZ2RvV5jWJ9NV4M3sxHszxd4WZ4iyXTwm";
    int res = -1;

    tx = calloc(1, sizeof(*tx));
    res = kyk_deseri_tx(tx, TX_43fcd_BUF, &check_num);
    check(res ==0, "Failed to test_kyk_get_addr_from_txout: kyk_deseri_tx failed");

    txout = tx -> txout;

    res = kyk_get_addr_from_txout(&btc_addr, txout);
    mu_assert(res == 0, "Failed to test_kyk_get_addr_from_txout");
    mu_assert(strcmp(btc_addr, expect_addr) == 0, "Failed to test_kyk_get_addr_from_txout");
    
    return NULL;

error:

    return "Failed to test_kyk_get_addr_from_txout";
}

char* test2_kyk_get_addr_from_txout()
{
    struct kyk_tx* tx = NULL;
    struct kyk_txout* txout = NULL;
    char* btc_addr = NULL;
    const char* expect_addr = "16zR6bvFXDvLJW4Gy4kCPNCNbZST4zUmfb";
    int res = -1;

    tx = calloc(1, sizeof(*tx));
    res = kyk_deseri_tx(tx, TX_27d0f_BUF, NULL);
    check(res ==0, "Failed to test_kyk_get_addr_from_txout: kyk_deseri_tx failed");

    txout = tx -> txout;

    res = kyk_get_addr_from_txout(&btc_addr, txout);
    mu_assert(res == 0, "Failed to test_kyk_get_addr_from_txout");
    mu_assert(strcmp(btc_addr, expect_addr) == 0, "Failed to test_kyk_get_addr_from_txout");
    
    return NULL;

error:

    return "Failed to test_kyk_get_addr_from_txout";
}

char* test_kyk_copy_new_tx()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx_cpy = NULL;
    uint8_t* buf = NULL;
    size_t buf_len = 0;
    int res = -1;

    res = kyk_deseri_new_tx(&tx, VIN4_TX, NULL);
    check(res == 0, "Failed to test_kyk_copy_new_tx: kyk_deseri_new_tx failed");

    res = kyk_copy_new_tx(&tx_cpy, tx);
    mu_assert(res == 0, "Failed to test_kyk_copy_new_tx");

    res = kyk_seri_tx_to_new_buf(tx, &buf, &buf_len);
    res = kyk_digest_eq(buf, VIN4_TX, buf_len);
    mu_assert(res == 1, "Failed to test_kyk_copy_new_tx");

    return NULL;

error:

    return "Failed to test_kyk_copy_new_tx";
}

char* test_kyk_copy_txout()
{
    return NULL;
}

char* test_kyk_seri_tx_for_sig()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx1 = NULL;
    uint8_t* buf = NULL;
    size_t buf_len = 0;
    int res = -1;

    kyk_deseri_new_tx(&tx, VIN4_TX, NULL);
    kyk_deseri_new_tx(&tx1, PRE_VIN4_TX1, NULL);

    res = kyk_seri_tx_for_sig(tx, HTYPE_SIGHASH_ALL, 0, tx1 -> txout, &buf, &buf_len);
    mu_assert(res == 0, "Failed to test_kyk_seri_tx_for_sig");
    
    return NULL;
}


char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_get_tx_size);
    mu_run_test(test_create_tx);
    mu_run_test(test_seri_tx);
    mu_run_test(test_seri_tx_list);
    mu_run_test(test2_seri_tx_list);
    mu_run_test(test_deseri_tx);
    mu_run_test(test_deseri_tx_list);
    mu_run_test(test_make_coinbase_tx);
    mu_run_test(test_kyk_get_addr_from_txout);
    mu_run_test(test2_kyk_get_addr_from_txout);
    mu_run_test(test_kyk_copy_txout);
    mu_run_test(test_deseri_new_tx);
    mu_run_test(test_kyk_seri_tx_for_sig);
    mu_run_test(test_kyk_copy_new_tx);
    
    return NULL;
}


/* The test data source is: https://webbtc.com/tx/b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082.json */
/* Txid is b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082 */
int build_testing_tx1(struct kyk_tx** out_tx)
{
    struct kyk_tx* tx = NULL;
    struct kyk_txin* txin = NULL;
    struct kyk_txout* txout = NULL;
    char* txout_sc = "4104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac";
    size_t txout_sc_size = 67;
    int res = -1;

    check(out_tx, "Failed to build_testing_tx1: out_tx is NULL");

    txin = create_txin(COINBASE_PRE_TXID,
		       COINBASE_INX,
		       7,
		       "04ffff001d0102",
		       NORMALLY_TX_SEQ_NO);
    
    check(txin, "Failed to test_seri_tx: create_txin failed");

    
    txout = create_txout(5000000000, (varint_t)txout_sc_size, txout_sc);
    check(txout, "Failed to test_seri_tx: create_txout failed");
    
    tx = kyk_create_tx(1, 1, 1, 0);
    check(tx, "Failed to test_seri_tx: kyk_create_tx failed");

    res = kyk_add_txin(tx, 0, txin);
    check(res == 0, "Failed to build_testing_tx1: kyk_add_txin failed");

    res = kyk_add_txout(tx, 0, txout);
    check(res == 0, "Failed to build_testing_tx1: kyk_add_txout failed");

    kyk_free_txin(txin);
    kyk_free_txout(txout);
    
    *out_tx = tx;
    return 0;

error:

    return -1;

}


MU_RUN_TESTS(all_tests);
