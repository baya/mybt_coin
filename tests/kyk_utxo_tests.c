#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_data.h"
#include "kyk_buff.h"
#include "kyk_tx.h"
#include "kyk_utils.h"
#include "kyk_utxo.h"
#include "mu_unit.h"

int build_testing_utxo(struct kyk_utxo** new_utxo);

char* test_kyk_get_utxo_size()
{
    struct kyk_utxo utxo;
    size_t len = 0;
    size_t expect_len = 136;
    int res = -1;
    
    utxo.addr_len = 34;
    utxo.btc_addr = "142SuQBUHiBAmcQgNL9Dbhj1aEYuCRmtSv";
    utxo.sc_size = 23;

    res = kyk_get_utxo_size(&utxo, &len);
    mu_assert(res == 0, "Failed to test_kyk_get_utxo_size");
    mu_assert(len == expect_len, "Failed to test_kyk_get_utxo_size");

    return NULL;
}

char* test_kyk_seri_utxo()
{
    struct kyk_utxo* utxo = NULL;
    uint8_t buf[1000];
    size_t len = 0;
    int res = -1;

    build_testing_utxo(&utxo);
    check(utxo, "Failed to test_kyk_seri_utxo: build_testing_utxo failed");

    res = kyk_seri_utxo(buf, utxo, &len);
    mu_assert(res == 0, "Failed to test_kyk_seri_utxo");

    kyk_free_utxo(utxo);
    
    return NULL;

error:

    return "Failed to test_kyk_seri_utxo";
}


char* test_kyk_deseri_utxo()
{
    struct kyk_utxo* utxo = NULL;
    int res = -1;
    size_t check_num; 

    res = kyk_deseri_utxo(&utxo, UTXO_BUF, &check_num);
    mu_assert(res == 0, "Failed to test_kyk_deseri_utxo");
    mu_assert(check_num == sizeof(UTXO_BUF), "Failed to test_kyk_deseri_tuxo");

    kyk_free_utxo(utxo);
    
    return NULL;
}


char* test_kyk_deseri_utxo_chain()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    int res = -1;
    size_t check_num = 0;

    res = kyk_deseri_utxo_chain(&utxo_chain, UTXO_BUF, 1, &check_num);
    mu_assert(res == 0, "Failed to test_kyk_deseri_utxo_chain");

    return NULL;
    
}


char* test_kyk_make_utxo()
{
    uint8_t blkhash[] ={
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xb6, 0x3f,
	0xb1, 0xc9, 0x2f, 0x21, 0xb3, 0x61, 0xb6, 0xb8,
	0xbb, 0xc4, 0x0b, 0xb5, 0xf5, 0x7e, 0x21, 0x97,
	0xb2, 0x53, 0x25, 0xff, 0x23, 0xbf, 0x85, 0x17
    };

    uint8_t txid[] = {
	0x73, 0xd6, 0xac, 0xba, 0x92, 0xd6, 0xdf, 0xaf,
	0x20, 0x4c, 0x0b, 0x4d, 0xd7, 0xcc, 0x56, 0x1a,
	0x96, 0xf5, 0x5c, 0x03, 0xe9, 0xbc, 0x15, 0x1d,
	0x9f, 0x6e, 0x2a, 0x0d, 0x7b, 0x94, 0x3f, 0xcd
    };
    
    struct kyk_tx* tx = NULL;
    struct kyk_utxo* utxo = NULL;
    uint32_t txout_idx = 0;
    const char* expect_addr = "1LZ2RvV5jWJ9NV4M3sxHszxd4WZ4iyXTwm";
    int res = -1;

    tx = malloc(sizeof(*tx));
    res = kyk_deseri_tx(tx, TX_43fcd_BUF, NULL);
    check(res ==0, "Failed to test_kyk_get_addr_from_txout: kyk_deseri_tx failed");

    res = kyk_make_utxo(&utxo, txid, blkhash, tx -> txout, txout_idx);
    mu_assert(res == 0, "Failed to test_kyk_make_utxo");
    mu_assert(strcmp(utxo -> btc_addr, expect_addr) == 0, "Failed to test_kyk_make_utxo");
    
    return NULL;

error:

    return "Failed to test_kyk_make_utxo";
}

char* test_kyk_valid_utxo_chain()
{
    struct kyk_utxo* utxo = NULL;
    struct kyk_utxo_chain* utxo_chain = NULL;
    int res = -1;

    res = build_testing_utxo(&utxo);
    check(res == 0, "Failed to test_kyk_valid_utxo_chain");

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    kyk_init_utxo_chain(utxo_chain);
    res = kyk_valid_utxo_chain(utxo_chain);
    mu_assert(res == 0, "Failed to test_kyk_valid_utxo_chain");

    utxo_chain -> hd = utxo;
    res = kyk_valid_utxo_chain(utxo_chain);
    mu_assert(res == -1, "Failed to test_kyk_valid_utxo_chain");

    utxo_chain -> tail = utxo;
    res = kyk_valid_utxo_chain(utxo_chain);
    mu_assert(res == 0, "Failed to test_kyk_valid_utxo_chain");

    return NULL;
error:
    if(utxo) kyk_free_utxo(utxo);
    return "Failed to test_kyk_valid_utxo_chain";
}

char* test_kyk_combine_utxo_chain()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_utxo_chain* utxo_chain1 = NULL;

    uint8_t expect_txid[] = {
	0x73, 0xd6, 0xac, 0xba, 0x92, 0xd6, 0xdf, 0xaf,
	0x20, 0x4c, 0x0b, 0x4d, 0xd7, 0xcc, 0x56, 0x1a,
	0x96, 0xf5, 0x5c, 0x03, 0xe9, 0xbc, 0x15, 0x1d,
	0x9f, 0x6e, 0x2a, 0x0d, 0x7b, 0x94, 0x3f, 0xcd
    };

    int res = -1;

    utxo_chain1 = calloc(1, sizeof(*utxo_chain1));

    res = kyk_deseri_utxo_chain(&utxo_chain, UTXO_BUF, 1, NULL);
    check(res == 0, "Failed to test_kyk_combine_utxo_chain: kyk_deseri_tuxo_chain Failed");

    res = kyk_combine_utxo_chain(utxo_chain1, utxo_chain);
    mu_assert(res == 0, "Failed to test_kyk_combine_utxo_chain");
    mu_assert(kyk_digest_eq(utxo_chain1 -> hd -> txid, expect_txid, sizeof(expect_txid)), "Failed to test_kyk_combine_utxo_chain");

    kyk_free_utxo_chain(utxo_chain1);
    free(utxo_chain);
    
    return NULL;

error:

    return "Failed to test_kyk_combine_utxo_chain";
}


char* test_kyk_append_utxo_chain_from_tx()
{
    struct kyk_block* blk = NULL;
    struct kyk_utxo_chain* utxo_chain= NULL;
    uint8_t blkhash[32];
    int res = -1;

    res = kyk_deseri_block(&blk, BLOCK_f8517_BUF, NULL);
    check(res == 0, "Failed to test_kyk_append_utxo_chain_from_tx: kyk_deseri_block failed");

    utxo_chain = malloc(sizeof(*utxo_chain));
    kyk_init_utxo_chain(utxo_chain);
    kyk_blk_hash256(blkhash, blk -> hd);

    res = kyk_append_utxo_chain_from_tx(utxo_chain, blkhash, blk -> tx);
    mu_assert(res == 0, "Failed to test_kyk_append_utxo_chain_from_tx");
    
    return NULL;

error:

    return "Failed to test_kyk_append_utxo_chain_from_tx";
}

char* test_kyk_append_utxo_chain_from_block()
{
    struct kyk_block* blk = NULL;
    struct kyk_utxo_chain* utxo_chain= NULL;
    uint8_t expect_blkhash[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xb6, 0x3f,
	0xb1, 0xc9, 0x2f, 0x21, 0xb3, 0x61, 0xb6, 0xb8,
	0xbb, 0xc4, 0x0b, 0xb5, 0xf5, 0x7e, 0x21, 0x97,
	0xb2, 0x53, 0x25, 0xff, 0x23, 0xbf, 0x85, 0x17
    };
    int res = -1;

    res = kyk_deseri_block(&blk, BLOCK_f8517_BUF, NULL);
    check(res == 0, "Failed to test_kyk_append_utxo_chain_from_tx: kyk_deseri_block failed");

    utxo_chain = malloc(sizeof(*utxo_chain));
    kyk_init_utxo_chain(utxo_chain);

    res = kyk_append_utxo_chain_from_block(utxo_chain, blk);
    mu_assert(res == 0, "Failed to test_kyk_append_utxo_chain_from_block");
    mu_assert(kyk_digest_eq(utxo_chain -> hd -> blkhash, expect_blkhash, sizeof(expect_blkhash)), "Failed to test_kyk_append_utxo_chain_from_block");
    
    return NULL;

error:
    return "Failed to test_kyk_append_utxo_chain_from_block";
}

char* test_kyk_get_utxo_chain_size()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    size_t chain_size = 0;
    int res = -1;

    res = kyk_deseri_utxo_chain(&utxo_chain, UTXO_BUF, 1, NULL);
    check(res == 0, "Failed to test_kyk_get_utxo_chain_size: kyk_deseri_tuxo_chain Failed");

    res = kyk_get_utxo_chain_size(utxo_chain, &chain_size);
    mu_assert(res == 0, "Failed to test_kyk_get_utxo_chain_size");
    mu_assert(chain_size == sizeof(UTXO_BUF), "Failed to test_kyk_get_utxo_chain_size");

    return NULL;

error:

    return "Failed to test_kyk_get_utxo_chain_size";
}

char* test_kyk_seri_utxo_chain()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    uint8_t* buf = NULL;
    size_t chain_size = 0;
    int res = -1;

    res = kyk_deseri_utxo_chain(&utxo_chain, UTXO_BUF, 1, NULL);
    check(res == 0, "Failed to test_kyk_seri_utxo_chain: kyk_deseri_tuxo_chain Failed");

    res = kyk_get_utxo_chain_size(utxo_chain, &chain_size);
    check(res == 0, "Failed to kyk_seri_utxo_chain: kyk_get_utxo_chain_size");

    buf = calloc(chain_size, sizeof(*buf));
    check(buf, "Failed to kyk_seri_utxo_chain: buf calloc failed");

    res = kyk_seri_utxo_chain(buf, utxo_chain, &chain_size);
    mu_assert(res == 0, "Failed to test_kyk_seri_utxo_chain");
    mu_assert(kyk_digest_eq(buf, UTXO_BUF, chain_size), "Failed to test_kyk_seri_utxo_chain");

    free(buf);
    kyk_free_utxo_chain(utxo_chain);
    
    return NULL;

error:
    if(buf) free(buf);
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return "Failed to test_kyk_seri_utxo_chain";
}


char *all_tests()
{
    mu_suite_start();

    mu_run_test(test_kyk_get_utxo_size);
    mu_run_test(test_kyk_seri_utxo);
    mu_run_test(test_kyk_deseri_utxo);
    mu_run_test(test_kyk_deseri_utxo_chain);
    mu_run_test(test_kyk_make_utxo);
    mu_run_test(test_kyk_valid_utxo_chain);
    mu_run_test(test_kyk_combine_utxo_chain);
    mu_run_test(test_kyk_append_utxo_chain_from_tx);
    mu_run_test(test_kyk_append_utxo_chain_from_block);
    mu_run_test(test_kyk_get_utxo_chain_size);
    mu_run_test(test_kyk_seri_utxo_chain);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);


/* https://webbtc.com/tx/73d6acba92d6dfaf204c0b4dd7cc561a96f55c03e9bc151d9f6e2a0d7b943fcd.json */
int build_testing_utxo(struct kyk_utxo** new_utxo)
{
    struct kyk_utxo* utxo = NULL;
    
    uint8_t txid[32] = {
	0x73, 0xd6, 0xac, 0xba, 0x92, 0xd6, 0xdf, 0xaf,
	0x20, 0x4c, 0x0b, 0x4d, 0xd7, 0xcc, 0x56, 0x1a,
	0x96, 0xf5, 0x5c, 0x03, 0xe9, 0xbc, 0x15, 0x1d,
	0x9f, 0x6e, 0x2a, 0x0d, 0x7b, 0x94, 0x3f, 0xcd
    };

    uint8_t blkhash[32] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xb6, 0x3f,
	0xb1, 0xc9, 0x2f, 0x21, 0xb3, 0x61, 0xb6, 0xb8,
	0xbb, 0xc4, 0x0b, 0xb5, 0xf5, 0x7e, 0x21, 0x97,
	0xb2, 0x53, 0x25, 0xff, 0x23, 0xbf, 0x85, 0x17
    };

    uint8_t sc[24] = {
	0xa9, 0x14, 0xd6, 0x78, 0xe4, 0xe4, 0xc7, 0x40,
	0xaa, 0x77, 0x25, 0x53, 0x02, 0xc4, 0x67, 0x04,
	0x2e, 0x7c, 0xe2, 0xa3, 0x19, 0x82, 0x88, 0xac
    };

    utxo = calloc(1, sizeof(*utxo));
    check(utxo, "Failed to build_testing_utxo: utxo calloc failed");

    memcpy(utxo -> txid, txid, sizeof(txid));
    memcpy(utxo -> blkhash, blkhash, sizeof(blkhash));
    utxo -> addr_len = 34;
    utxo -> btc_addr = calloc(utxo -> addr_len, sizeof(*utxo -> btc_addr));
    memcpy(utxo -> btc_addr, "1LZ2RvV5jWJ9NV4M3sxHszxd4WZ4iyXTwm", utxo -> addr_len);
    utxo -> outidx = 0;
    utxo -> value = 800000000;
    utxo -> sc_size = sizeof(sc);
    utxo -> sc = calloc(utxo -> sc_size, sizeof(*utxo -> sc));
    memcpy(utxo -> sc, sc, sizeof(sc));
    utxo -> spent = 0;

    *new_utxo = utxo;

    return 0;

error:
    return -1;
    
}
