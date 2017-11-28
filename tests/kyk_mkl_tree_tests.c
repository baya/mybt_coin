#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_block.h"
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


char* test2_make_mkl_tree_root_from_tx_list()
{
    
   /* block file is sourced from: https://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.bin */
   /* The json format is: https://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.json */
   /* This block has 2 Tx, each txid is following: */
   /* b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082 */
   /* f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 */
   /* the mrkl root is 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff */
    const char* blkfile = "data/blk_00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.dat";    
    struct kyk_block* blk = NULL;
    struct kyk_tx* tx_list = NULL;
    size_t blk_size = 0;
    size_t tx_count = 0;
    struct kyk_mkltree_level* mkl_rt;
    int res = -1;
    const uint8_t target_rt[32] = {
	0x7d, 0xac, 0x2c, 0x56, 0x66, 0x81, 0x5c, 0x17,
	0xa3, 0xb3, 0x64, 0x27, 0xde, 0x37, 0xbb, 0x9d,
	0x2e, 0x2c, 0x5c, 0xce, 0xc3, 0xf8, 0x63, 0x3e,
	0xb9, 0x1a, 0x42, 0x05, 0xcb, 0x4c, 0x10, 0xff	
    };

    uint8_t buf[600];

    FILE* fp = fopen(blkfile, "rb");
    check(fp, "Failed to test2_make_mkl_tree_root_from_tx_list: fopen blkfile failed");
    fread(buf, sizeof(buf), 1, fp);
    fclose(fp);
    fp = NULL;

    blk = calloc(1, sizeof(*blk));
    check(blk, "Failed to test2_make_mkl_tree_root_from_tx_list: blk calloc failed");

    // res = kyk_deseri_block(blk, BLOCK_2TX_BUF, &blk_size);
    res = kyk_deseri_block(blk, buf, &blk_size);
    check(res == 0, "Failed to test2_make_mkl_tree_root_from_tx_list: kyk_deseri_block failed");
    
    tx_list = blk -> tx;
    tx_count = blk -> tx_count;
    mkl_rt = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_rt, "Failed to test2_make_mkl_tree_root_from_tx_list: kyk_make_mkl_tree_root_from_tx_list failed");
    mu_assert(kyk_digest_eq(mkl_rt -> nd -> bdy, target_rt, sizeof(target_rt)), "Failed to test_make_mkl_tree_root_from_tx_list");

    res = kyk_free_mkl_tree(mkl_rt);
    mkl_rt = NULL;
    check(res == 0, "test2_make_mkl_tree_root_from_tx_list: kyk_free_mkl_tree failed");

    return NULL;
error:

    return "test2_make_mkl_tree_root_from_tx_list failed";
}


char* test6_make_mkl_tree_root_from_tx_list()
{
    /* blk file is sourced from https://webbtc.com/block/000000000000000002374f6983212149a67c394acae72926c88db2cf21db48bf.bin */
    /* its json format is https://webbtc.com/block/000000000000000002374f6983212149a67c394acae72926c88db2cf21db48bf.json */
    /* and its mrkl_root is 61839c14b1da5be6544fa8c0ea615d7ddccbbd832047c49ebaa0e0b044377d12 */
    const char* blkfile = "data/blk_000000000000000002374f6983212149a67c394acae72926c88db2cf21db48bf.dat";
    
    struct kyk_block* blk = NULL;
    struct kyk_tx* tx_list = NULL;
    size_t blk_size = 0;
    size_t tx_count = 0;
    struct kyk_mkltree_level* mkl_rt;
    int res = -1;
    const uint8_t target_rt[32] = {
	0x61, 0x83, 0x9c, 0x14, 0xb1, 0xda, 0x5b, 0xe6,
	0x54, 0x4f, 0xa8, 0xc0, 0xea, 0x61, 0x5d, 0x7d,
	0xdc, 0xcb, 0xbd, 0x83, 0x20, 0x47, 0xc4, 0x9e,
	0xba, 0xa0, 0xe0, 0xb0, 0x44, 0x37, 0x7d, 0x12	
    };
    uint8_t buf[3000];

    FILE* fp = fopen(blkfile, "rb");
    check(fp, "Failed to test6_make_mkl_tree_root_from_tx_list: fopen blkfile failed");
    fread(buf, sizeof(buf), 1, fp);
    fclose(fp);
    fp = NULL;

    blk = malloc(sizeof(*blk));
    check(blk, "Failed to test6_make_mkl_tree_root_from_tx_list: blk malloc failed");
    blk -> hd = NULL;
    blk -> tx = NULL;

    res = kyk_deseri_block(blk, buf, &blk_size);
    check(res == 0, "Failed to test6_make_mkl_tree_root_from_tx_list: kyk_deseri_block failed");
    
    tx_list = blk -> tx;
    tx_count = blk -> tx_count;
    mkl_rt = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_rt, "Failed to test6_make_mkl_tree_root_from_tx_list: kyk_make_mkl_tree_root_from_tx_list failed");
    mu_assert(kyk_digest_eq(mkl_rt -> nd -> bdy, target_rt, sizeof(target_rt)), "Failed to test_make_mkl_tree_root_from_tx_list");

    kyk_free_block(blk);
    blk = NULL;
    res = kyk_free_mkl_tree(mkl_rt);
    mkl_rt = NULL;
    check(res == 0, "test6_make_mkl_tree_root_from_tx_list: kyk_free_mkl_tree failed");

    return NULL;
error:
    if(fp) fclose(fp);
    return "test6_make_mkl_tree_root_from_tx_list failed";
}


char* test15_make_mkl_tree_root_from_tx_list()
{
    /* block file is sourced from https://webbtc.com/block/00000000000000000630790598c5bf4130d9811515c8dd5c6131ea3c56e48ac8.bin */
    /* and the json format is https://webbtc.com/block/00000000000000000630790598c5bf4130d9811515c8dd5c6131ea3c56e48ac8.json */
    /* its mrkl tree is: */
    /* "b607ddc194f7be5e2b1f0df25754f7c2db20b1b50c6c2ce53e34b54bc502d0d9" */
    const char* blkfile = "data/blk_00000000000000000630790598c5bf4130d9811515c8dd5c6131ea3c56e48ac8.dat";
    struct kyk_block* blk = NULL;
    struct kyk_tx* tx_list = NULL;
    size_t blk_size = 0;
    size_t tx_count = 0;
    struct kyk_mkltree_level* mkl_rt;
    int res = -1;
    const uint8_t target_rt[32] = {
	0xb6, 0x07, 0xdd, 0xc1, 0x94, 0xf7, 0xbe, 0x5e,
	0x2b, 0x1f, 0x0d, 0xf2, 0x57, 0x54, 0xf7, 0xc2,
	0xdb, 0x20, 0xb1, 0xb5, 0x0c, 0x6c, 0x2c, 0xe5,
	0x3e, 0x34, 0xb5, 0x4b, 0xc5, 0x02, 0xd0, 0xd9	
    };

    uint8_t buf[6000];
    FILE* fp = fopen(blkfile, "rb");
    check(fp, "Failed to test15_make_mkl_tree_root_from_tx_list: fopen blkfile failed");
    fread(buf, sizeof(buf), 1, fp);
    fclose(fp);
    fp = NULL;

    blk = malloc(sizeof(*blk));
    check(blk, "Failed to test15_make_mkl_tree_root_from_tx_list: blk malloc failed");
    blk -> hd = NULL;
    blk -> tx = NULL;

    res = kyk_deseri_block(blk, buf, &blk_size);
    check(res == 0, "Failed to test15_make_mkl_tree_root_from_tx_list: kyk_deseri_block failed");
    
    tx_list = blk -> tx;
    tx_count = blk -> tx_count;
    mkl_rt = kyk_make_mkl_tree_root_from_tx_list(tx_list, tx_count);
    check(mkl_rt, "Failed to test15_make_mkl_tree_root_from_tx_list: kyk_make_mkl_tree_root_from_tx_list failed");
    mu_assert(kyk_digest_eq(mkl_rt -> nd -> bdy, target_rt, sizeof(target_rt)), "Failed to test_make_mkl_tree_root_from_tx_list");

    kyk_free_block(blk);
    blk = NULL;
    res = kyk_free_mkl_tree(mkl_rt);
    mkl_rt = NULL;
    check(res == 0, "test15_make_mkl_tree_root_from_tx_list: kyk_free_mkl_tree failed");

    return NULL;
error:
    if(fp) fclose(fp);
    return "test15_make_mkl_tree_root_from_tx_list failed";
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_mkl_tree_root_from_tx_list);
    mu_run_test(test2_make_mkl_tree_root_from_tx_list);
    mu_run_test(test6_make_mkl_tree_root_from_tx_list);
    mu_run_test(test15_make_mkl_tree_root_from_tx_list);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
