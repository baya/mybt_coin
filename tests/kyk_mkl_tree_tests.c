#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_buff.h"
#include "kyk_tx.h"
#include "kyk_utils.h"
#include "kyk_mkl_tree.h"
#include "mu_unit.h"

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


char* test_make_mkl_tree_root_from_tx_list()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx_list = NULL;
    struct kyk_mkltree_level* mkl_rt;
    size_t tx_count = 1;
    int res = -1;
    const uint8_t target_rt[32] = {
	0xb1, 0xfe, 0xa5, 0x24, 0x86, 0xce, 0x0c, 0x62,
	0xbb, 0x44, 0x2b, 0x53, 0x0a, 0x3f, 0x01, 0x32,
	0xb8, 0x26, 0xc7, 0x4e, 0x47, 0x3d, 0x1f, 0x2c,
	0x22, 0x0b, 0xfa, 0x78, 0x11, 0x1c, 0x50, 0x82
    };

    tx_list = calloc(tx_count, sizeof(struct kyk_tx));
    check(tx_list, "Failed to calloc tx_list");
    
    res = build_testing_tx1(&tx);
    check(res == 0, "Failed to build_testing_tx1");

    res = kyk_copy_tx(tx_list, tx);
    check(res == 0, "Failed to kyk_copy_tx");

    mkl_rt = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_rt, "Failed to kyk_make_mkl_tree_root_from_tx_list");
    mu_assert(kyk_digest_eq(mkl_rt -> nd -> bdy, target_rt, sizeof(target_rt)), "Failed to test_make_mkl_tree_root_from_tx_list");

    return NULL;

error:

    return "test_make_mkl_tree_root_from_tx_list failed";
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_mkl_tree_root_from_tx_list);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
