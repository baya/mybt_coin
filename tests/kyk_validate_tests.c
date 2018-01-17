#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "test_data.h"
#include "kyk_block.h"
#include "kyk_validate.h"
#include "kyk_utxo.h"
#include "mu_unit.h"


char* test_kyk_validate_blk_header()
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_block* blk = NULL;
    const uint8_t pubkey[33] = {
	0x02, 0x76, 0xe9, 0xd1, 0x87, 0x81, 0xd2, 0xb3,
	0xad, 0x7e, 0x5a, 0xc8, 0xd3, 0x8e, 0xf0, 0x89,
	0x9f, 0x94, 0x42, 0xf8, 0x09, 0xbb, 0xbc, 0x67,
	0xe5, 0x27, 0x27, 0x8d, 0xa2, 0xae, 0xdc, 0x93,
	0xa4
    };
    const char* note = "voidcoin";
    int res = -1;

    res = kyk_deseri_blk_hd_chain(&hd_chain, BTC_012_BLK_HD_BUF, sizeof(BTC_012_BLK_HD_BUF));
    check(res == 0, "Failed to test_kyk_validate_blk_header: kyk_deseri_blk_hd_chain failed");

    res = kyk_make_coinbase_block(&blk, hd_chain, note, pubkey, sizeof(pubkey));
    check(res == 0, "Failed to test_kyk_validate_blk_header: kyk_make_coinbase_block failed");

    res = kyk_validate_blk_header(hd_chain, blk -> hd);
    mu_assert(res == 0, "Failed to test_kyk_validate_blk_header");

    return NULL;

error:

    return "Failed to test_kyk_validate_blk_header";
}


char* test2_kyk_validate_blk_header()
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_blk_header* hd = NULL;
    int res = -1;

    res = kyk_deseri_blk_hd_chain(&hd_chain, BTC_012_BLK_HD_BUF, sizeof(BTC_012_BLK_HD_BUF));
    check(res == 0, "Failed to test_kyk_validate_blk_header: kyk_deseri_blk_hd_chain failed");

    hd = calloc(1, sizeof(*hd));

    memcpy(hd -> pre_blk_hash, BTC_1_BLK_HD_BUF, sizeof(hd -> pre_blk_hash));
    res = kyk_validate_blk_header(hd_chain, hd);
    mu_assert(res == -1, "Failed to test_kyk_validate_blk_header");

    return NULL;

error:

    return "Failed to test_kyk_validate_blk_header";
}

char* test_kyk_validate_block()
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_block* blk = NULL;
    size_t check_size = 0;
    int res = -1;

    res = kyk_deseri_blk_hd_chain(&hd_chain, BTC_01_BLK_HD_BUF, sizeof(BTC_01_BLK_HD_BUF));
    check(res == 0, "Failed to test_kyk_validate_block: kyk_deseri_blk_hd_chain failed");

    res = kyk_deseri_new_block(&blk, BTC_2_BLOCK_BUF, &check_size);
    check(res == 0, "Failed to test_kyk_validate_block: kyk_deseri_new_block failed");

    res = kyk_validate_block(hd_chain, blk);
    mu_assert(res == 0, "Failed to test_kyk_validate_block");
    
    return NULL;

error:
    
    return "Failed to test_kyk_validate_block";
}

char* test_kyk_validate_txin_script_sig()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx1 = NULL;
    struct kyk_tx* tx2 = NULL;
    struct kyk_tx* tx3 = NULL;
    struct kyk_tx* tx4 = NULL;
    struct kyk_txin* txin = NULL;

    uint8_t* buf = NULL;
    size_t buf_len = 0;
    int res = -1;

    kyk_deseri_new_tx(&tx, VIN4_TX, NULL);

    res = build_testing_vin4_tx_unsig_buf(0, &buf, &buf_len);
    check(res == 0, "Failed to test_kyk_validate_txin_script_sig: build_testing_vin4_tx_unsig_buf failed");
    kyk_deseri_new_tx(&tx1, PRE_VIN4_TX1, NULL);
    txin = tx -> txin + 0;
    res = kyk_validate_txin_script_sig(txin, buf, buf_len, tx1);
    mu_assert(res == 0, "Failed to test_kyk_validate_txin_script_sig");

    res = build_testing_vin4_tx_unsig_buf(1, &buf, &buf_len);
    check(res == 0, "Failed to test_kyk_validate_txin_script_sig: build_testing_vin4_tx_unsig_buf failed");
    kyk_deseri_new_tx(&tx2, PRE_VIN4_TX2, NULL);
    txin = tx -> txin + 1;
    res = kyk_validate_txin_script_sig(txin, buf, buf_len, tx2);
    mu_assert(res == 0, "Failed to test_kyk_validate_txin_script_sig");

    res = build_testing_vin4_tx_unsig_buf(2, &buf, &buf_len);
    check(res == 0, "Failed to test_kyk_validate_txin_script_sig: build_testing_vin4_tx_unsig_buf failed");
    kyk_deseri_new_tx(&tx3, PRE_VIN4_TX3, NULL);
    txin = tx -> txin + 2;
    res = kyk_validate_txin_script_sig(txin, buf, buf_len, tx3);    
    mu_assert(res == 0, "Failed to test_kyk_validate_txin_script_sig");

    res = build_testing_vin4_tx_unsig_buf(3, &buf, &buf_len);
    check(res == 0, "Failed to test_kyk_validate_txin_script_sig: build_testing_vin4_tx_unsig_buf failed");
    kyk_deseri_new_tx(&tx4, PRE_VIN4_TX4, NULL);
    txin = tx -> txin + 3;
    res = kyk_validate_txin_script_sig(txin, buf, buf_len, tx4);
    mu_assert(res == 0, "Failed to test_kyk_validate_txin_script_sig");
    

    return NULL;

error:

    return "Failed to test_kyk_validate_txin_script_sig";
}

char* test2_kyk_validate_txin_script_sig()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx1 = NULL;
    uint8_t* buf = NULL;
    size_t buf_len = 0;
    int res = -1;

    res = build_testing_vin1_tx_unsig_buf(0, &buf, &buf_len);
    check(res == 0, "Failed to test2_kyk_validate_txin_script_sig: build_testing_vin1_tx_unsig_buf failed");

    kyk_deseri_new_tx(&tx, VIN1_TX, NULL);
    kyk_deseri_new_tx(&tx1, PRE_VIN1_TX1, NULL);

    res = kyk_validate_txin_script_sig(tx -> txin, buf, buf_len, tx1);
    mu_assert(res == 0, "Failed to test_kyk_validate_txin_script_sig");

    return NULL;

error:

    return "Failed to test2_kyk_validate_txin_script_sig";

}

char* test_kyk_validate_tx()
{
    struct kyk_tx* tx = NULL;
    struct kyk_tx* tx1 = NULL;
    struct kyk_tx* tx2 = NULL;
    struct kyk_tx* tx3 = NULL;
    struct kyk_tx* tx4 = NULL;
    struct kyk_utxo* utxo_list = NULL;
    struct kyk_utxo* utxo = NULL;
    uint8_t txid[32];
    uint8_t blkhash1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x4d, 0x7a, 0x36, 0x9f, 0xf0, 0x32, 0xb7,
	0x11, 0x9d, 0x65, 0xca, 0x29, 0xf4, 0x29, 0x46,
	0xd0, 0x0e, 0xe9, 0xe6, 0x07, 0xee, 0x4a, 0x7f
    };
    uint8_t blkhash2[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x4d, 0x7a, 0x36, 0x9f, 0xf0, 0x32, 0xb7,
	0x11, 0x9d, 0x65, 0xca, 0x29, 0xf4, 0x29, 0x46,
	0xd0, 0x0e, 0xe9, 0xe6, 0x07, 0xee, 0x4a, 0x7f
    };
    uint8_t blkhash3[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x74, 0xdb, 0x0e, 0xee, 0x0d, 0x88, 0x94,
	0x30, 0x2f, 0xb1, 0x5a, 0xbc, 0x7f, 0x8c, 0x85,
	0xa5, 0xeb, 0x03, 0x3d, 0xc8, 0x4c, 0x68, 0x9d
    };
    uint8_t blkhash4[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x74, 0xdb, 0x0e, 0xee, 0x0d, 0x88, 0x94,
	0x30, 0x2f, 0xb1, 0x5a, 0xbc, 0x7f, 0x8c, 0x85,
	0xa5, 0xeb, 0x03, 0x3d, 0xc8, 0x4c, 0x68, 0x9d
    };
    size_t len = 4;
    int res = -1;
    
    kyk_deseri_new_tx(&tx, VIN4_TX, NULL);
    kyk_deseri_new_tx(&tx1, PRE_VIN4_TX1, NULL);
    kyk_deseri_new_tx(&tx2, PRE_VIN4_TX2, NULL);
    kyk_deseri_new_tx(&tx3, PRE_VIN4_TX3, NULL);
    kyk_deseri_new_tx(&tx4, PRE_VIN4_TX4, NULL);

    utxo_list = calloc(len, sizeof(*utxo_list));
    utxo = utxo_list + 0;
    kyk_tx_hash256(txid, tx1);
    kyk_make_utxo(utxo, txid, blkhash1, tx1 -> txout + 1, 1);

    utxo = utxo_list + 1;
    kyk_tx_hash256(txid, tx2);
    kyk_make_utxo(utxo, txid, blkhash2, tx2 -> txout + 1, 1);

    utxo = utxo_list + 2;
    kyk_tx_hash256(txid, tx3);
    kyk_make_utxo(utxo, txid, blkhash3, tx3 -> txout + 0, 0);

    utxo = utxo_list + 3;
    kyk_tx_hash256(txid, tx4);
    kyk_make_utxo(utxo, txid, blkhash4, tx4 -> txout + 1, 1);

    res = kyk_validate_tx(tx, utxo_list, len);
    mu_assert(res == 0, "Failed to test_kyk_validate_tx");
	
    return NULL;
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_validate_blk_header);
    mu_run_test(test2_kyk_validate_blk_header);
    mu_run_test(test2_kyk_validate_txin_script_sig);
    mu_run_test(test_kyk_validate_txin_script_sig);
    mu_run_test(test_kyk_validate_tx);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
