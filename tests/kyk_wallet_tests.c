#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_data.h"
#include "kyk_utxo.h"
#include "kyk_wallet.h"
#include "kyk_utils.h"
#include "kyk_validate.h"
#include "mu_unit.h"

char* test_kyk_new_wallet()
{
    const char* wdir = "/tmp/test_kyk_new_wallet";
    struct kyk_wallet* wallet = NULL;

    wallet = kyk_new_wallet(wdir);
    mu_assert(wallet, "Failed to kyk_new_wallet");

    return NULL;
}

char* test_kyk_setup_wallet()
{
    const char* wdir = "/tmp/test_kyk_setup_wallet";
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    mu_assert(res == 0, "Failed to test_kyk_setup_wallet");
    mu_assert(wallet, "Failed to test_kyk_setup_wallet");
    
    return NULL;
}

char* test_kyk_open_wallet()
{
    const char* wdir = "/tmp/test_kyk_open_wallet";
    struct kyk_wallet* tmp_wallet = NULL;
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    res = kyk_setup_wallet(&tmp_wallet, wdir);
    check(res == 0, "Failed to test_kyk_open_wallet: kyk_setup_wallet failed");
    kyk_destroy_wallet(tmp_wallet);

    wallet = kyk_open_wallet(wdir);
    mu_assert(wallet, "Failed to test_kyk_open_wallet");
    
    kyk_destroy_wallet(wallet);
    
    return NULL;

error:

    return "Failed to test_kyk_open_wallet";
}

char* test_kyk_create_wallet_key()
{
    struct kyk_wallet_key* wkey = NULL;
    uint32_t cfg_idx = 0;
    const char* desc = "main key";
    char* errmsg = "failed to test kyk_create_wallet_key";
    
    wkey = kyk_create_wallet_key(cfg_idx, desc);
    check(wkey, "failed to kyk_create_wallet_key");
    mu_assert(wkey -> cfg_idx == cfg_idx, "failed to set the correct cfgidx");
    mu_assert(strcmp(wkey -> desc, desc) == 0, "failed to set the correct desc");
    
    return NULL;

error:
    return errmsg;
}

char* test_kyk_wallet_check_config()
{
    
    const char* wdir = "/tmp/test_kyk_wallet_check_config";
    struct kyk_wallet* wallet = NULL;
    char* errmsg = "failed to test kyk_wallet_check_config";
    int res = -1;
    
    wallet = calloc(1, sizeof *wallet);
    check(wallet != NULL, "failed to calloc");

    res = kyk_wallet_check_config(wallet, wdir);
    mu_assert(res == 0, "failed to test kyk_wallet_check_config");
    mu_assert(strcmp(wallet -> wdir, wdir) == 0, "failed to get the correct wallet wdir");
    

    return NULL;

error:
    return errmsg;
}


char* test_kyk_wallet_add_address()
{
    const char* wdir = "/tmp/test_kyk_wallet_add_address";
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    wallet = calloc(1, sizeof *wallet);
    check(wallet, "Failed to test_kyk_wallet_add_address: wallet calloc failed");
    res = kyk_wallet_check_config(wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_add_address: kyk_wallet_check_config failed");

    res = kyk_wallet_add_address(wallet, "test adding address");
    mu_assert(res == 0, "Failed to test_kyk_wallet_add_address");

    return NULL;

error:

    return "Failed to test_kyk_wallet_add_address";
}

char* test_kyk_save_blk_header_chain()
{
    const char* wdir = "/tmp/test_kyk_save_blk_head_chain";
    struct kyk_wallet* wallet = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    int res = -1;

    wallet = calloc(1, sizeof *wallet);
    check(wallet, "Failed to test_kyk_save_blk_head_chain: wallet calloc failed");
    res = kyk_wallet_check_config(wallet, wdir);
    check(res == 0, "Failed to test_kyk_save_blk_head_chain: kyk_wallet_check_config failed");

    res = make_testing_blk_hd_chain(&hd_chain);
    check(res == 0, "Failed to test_kyk_save_blk_head_chain: make_testing_blk_hd_chain failed");

    res = kyk_save_blk_header_chain(wallet, hd_chain, NULL);
    mu_assert(res == 0, "Failed to test_kyk_save_blk_head_chain");

    
    return NULL;

error:

    return "Failed to test_kyk_save_blk_head_chain";
}

char* test_kyk_wallet_get_pubkey()
{
    const char* wdir = "/tmp/test_kyk_wallet_get_pubkey";
    struct kyk_wallet* wallet = NULL;
    uint8_t* pubkey = NULL;
    size_t pbk_len = 0;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_get_pubkey: kyk_setup_wallet failed");

    res = kyk_wallet_get_pubkey(&pubkey, &pbk_len, wallet, "key0.pubkey");
    mu_assert(res == 0, "Failed to test_kyk_wallet_get_pubkey");
    mu_assert(pbk_len == 33, "Failed to test_kyk_wallet_get_pubkey");
    /* kyk_print_hex("pubkey", pubkey, pbk_len); */

    return NULL;

error:

    return "Failed to test_kyk_wallet_get_pubkey";
}

char* test_kyk_wallet_save_block()
{
    const char* wdir = "/tmp/test_kyk_wallet_save_block";
    struct kyk_wallet* wallet = NULL;
    struct kyk_block* blk = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_save_block: kyk_setup_wallet failed");

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, NULL);
    check(res == 0, "Failed to test_kyk_wallet_save_block: kyk_deseri_new_block failed");

    res = kyk_set_blkself_info(blk);
    check(res == 0, "Failed to test_kyk_wallet_save_block: failed to kyk_set_blkself_info");
    
    res = kyk_wallet_save_block(wallet, blk);
    mu_assert(res == 0, "Failed to test_kyk_wallet_save_block");

    kyk_destroy_wallet(wallet);

    return NULL;

error:
    if(wallet) kyk_destroy_wallet(wallet);
    return "Failed to test_kyk_wallet_save_block";
}

char* test_kyk_load_blk_header_chain()
{
    const char* wdir = "/tmp/test_kyk_load_blk_header_chain";
    struct kyk_wallet* wallet = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_load_blk_header_chain: kyk_setup_wallet failed");

    res = kyk_load_blk_header_chain(&hd_chain, wallet);
    mu_assert(res == 0, "Failed to test_kyk_load_blk_header_chain");

    return NULL;

error:

    return "Failed to test_kyk_load_blk_header_chain";
}

char* test_kyk_load_utxo_chain()
{
    const char* wdir = "/tmp/test_kyk_load_utxo_chain";
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_load_utxo_chain: kyk_setup_wallet failed");

    res = kyk_load_utxo_chain(&utxo_chain, wallet);
    mu_assert(res == 0, "Failed to test_kyk_load_utxo_chain");

    return NULL;

error:
    return "Failed to test_kyk_load_utxo_chain";
}

char* test_kyk_wallet_save_utxo_chain()
{
    const char* wdir = "/tmp/test_kyk_wallet_save_utxo_chain";
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_save_utxo_chain: kyk_setup_wallet failed");

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    res = kyk_deseri_utxo_chain(utxo_chain, UTXO_BUF, 1, NULL);
    check(res == 0, "Failed to test_kyk_wallet_save_utxo_chain: kyk_deseri_utxo_chain failed");

    res = kyk_wallet_save_utxo_chain(wallet, utxo_chain);
    mu_assert(res == 0, "Failed to test_kyk_wallet_save_utxo_chain");

    kyk_free_utxo_chain(utxo_chain);
    
    return NULL;

error:

    return "Failed to test_kyk_wallet_save_utxo_chain";
}

char* test_kyk_load_utxo_chain_from_chainfile_buf()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_utxo* utxo = NULL;
    int res = -1;

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    res = kyk_load_utxo_chain_from_chainfile_buf(utxo_chain, UTXO1_CHAIN_FILE_BUF, sizeof(UTXO1_CHAIN_FILE_BUF));
    mu_assert(res == 0, "Failed to test_kyk_load_utxo_chain_from_chainfile_buf");

    utxo = utxo_chain -> hd;
    while(utxo){
        kyk_print_utxo(utxo);
    	utxo = utxo -> next;
    }
    

    return NULL;
}


char* test2_kyk_load_utxo_chain_from_chainfile_buf()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_utxo* utxo = NULL;
    int res = -1;

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    res = kyk_load_utxo_chain_from_chainfile_buf(utxo_chain, UTXO7_CHAIN_FILE_BUF, sizeof(UTXO7_CHAIN_FILE_BUF));
    mu_assert(res == 0, "Failed to test_kyk_load_utxo_chain_from_chainfile_buf");
    mu_assert(utxo_chain -> len == 7, "Failed to test_kyk_load_utxo_chain_from_chainfile_buf");

    utxo = utxo_chain -> hd;
    while(utxo){
        kyk_print_utxo(utxo);
    	utxo = utxo -> next;
    }
    

    return NULL;
}

char* test_kyk_wallet_query_value_by_addr()
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    uint64_t value = 0;
    uint64_t expect_value = 70000000000;
    int res = -1;

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    res = kyk_load_utxo_chain_from_chainfile_buf(utxo_chain, UTXO7_CHAIN_FILE_BUF, sizeof(UTXO7_CHAIN_FILE_BUF));
    check(res == 0, "Failed to test_kyk_wallet_query_value_by_addr: kyk_load_utxo_chain_from_chainfile_buf failed");

    res = kyk_wallet_query_value_by_addr(btc_addr, utxo_chain, &value);
    mu_assert(res == 0, "Failed to test_kyk_wallet_query_value_by_addr");
    mu_assert(expect_value == value, "Failed to test_kyk_wallet_query_value_by_addr");

    return NULL;

error:

    return "Failed to test_wallet_query_value_by_addr";

}

char* test_kyk_wallet_load_addr_list()
{
    const char* wdir = "/tmp/test_kyk_wallet_load_addr_list";
    struct kyk_wallet* wallet = NULL;
    char** addr_list = NULL;
    size_t len = 0;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_load_addr_list: kyk_setup_wallet failed");

    res = kyk_wallet_load_addr_list(wallet, &addr_list, &len);
    mu_assert(res == 0, "Failed to test_kyk_wallet_load_addr_list");
    /* mu_assert(len == 1, "Failed to tst_kyk_wallet_load_addr_list"); */

    /* for(i = 0; i < len; i++){ */
    /* 	printf("btc address: %s\n", addr_list[i]); */
    /* } */

    return NULL;

error:

    return "Failed to test_kyk_wallet_load_addr_list";

}

char* test_kyk_wallet_make_tx()
{
    const char* wdir = "/tmp/test_kyk_wallet_make_tx";
    struct kyk_wallet* wallet = NULL;
    struct kyk_tx* new_tx = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    uint64_t btc_value = 1 * ONE_BTC_COIN_VALUE;
    uint32_t version = 1;
    struct kyk_block* blk = NULL;
    struct kyk_txout* txout = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* tx_utxo_chain = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_make_tx: kyk_setup_wallet failed");

    res = kyk_wallet_make_coinbase_block(&blk, wallet);
    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_utxo_chain failed");

    res = kyk_wallet_make_tx(&new_tx, &tx_utxo_chain, version, wallet, wallet_utxo_chain, btc_value, btc_addr);
    mu_assert(res == 0, "Failed to test_kyk_wallet_make_tx");
    /* kyk_print_tx(new_tx); */

    txout = blk -> tx -> txout;
    res = kyk_validate_tx_txin_script_sig(new_tx, 0, txout);
    mu_assert(res == 0, "Failed to test_kyk_wallet_make_tx");

    return NULL;

error:

    return "Failed to test_kyk_wallet_make_tx";
}


char* test2_kyk_wallet_make_tx()
{
    const char* wdir = "/tmp/test2_kyk_wallet_make_tx";
    struct kyk_wallet* wallet = NULL;
    struct kyk_tx* new_tx = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    uint64_t btc_value = 90 * ONE_BTC_COIN_VALUE;
    uint32_t version = 1;
    struct kyk_block* blk = NULL;
    struct kyk_txout* txout = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* tx_utxo_chain = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test2_kyk_wallet_make_tx: kyk_setup_wallet failed");

    res = kyk_wallet_make_coinbase_block(&blk, wallet);
    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_utxo_chain failed");

    res = kyk_wallet_make_tx(&new_tx, &tx_utxo_chain, version, wallet, wallet_utxo_chain, btc_value, btc_addr);
    mu_assert(res == 0, "Failed to test2_kyk_wallet_make_tx");
    /* kyk_print_tx(new_tx); */

    txout = blk -> tx -> txout;
    res = kyk_validate_tx_txin_script_sig(new_tx, 0, txout);
    mu_assert(res == 0, "Failed to test_kyk_wallet_make_tx");

    return NULL;

error:

    return "Failed to test2_kyk_wallet_make_tx";
}

/* sending btc num more than owned will cause failed */
char* test3_kyk_wallet_make_tx()
{
    const char* wdir = "/tmp/test3_kyk_wallet_make_tx";
    struct kyk_wallet* wallet = NULL;
    struct kyk_tx* new_tx = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    uint64_t btc_value = 110 * ONE_BTC_COIN_VALUE;
    uint32_t version = 1;
    struct kyk_block* blk = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* tx_utxo_chain = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test3_kyk_wallet_make_tx: kyk_setup_wallet failed");

    res = kyk_wallet_make_coinbase_block(&blk, wallet);
    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_utxo_chain failed");

    res = kyk_wallet_make_tx(&new_tx, &tx_utxo_chain, version, wallet, wallet_utxo_chain, btc_value, btc_addr);
    mu_assert(res == -1, "Failed to test3_kyk_wallet_make_tx");
    /* kyk_print_tx(new_tx); */

    return NULL;

error:

    return "Failed to test3_kyk_wallet_make_tx";
}

char* test_kyk_wallet_load_key_list()
{
    const char* wdir = "/tmp/test_kyk_wallet_load_key_list";
    struct kyk_wallet* wallet = NULL;
    struct kyk_wkey_chain* wkey_chain = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_load_key_list: kyk_setup_wallet failed");

    res = kyk_wallet_load_key_list(wallet, &wkey_chain);
    mu_assert(res == 0, "Failed to test_kyk_wallet_load_key_list");
    /* kyk_print_wkey_chain(wkey_chain); */

    return NULL;

error:

    return "Failed to test_kyk_wallet_load_key_list";
   
}


char* test_kyk_wallet_cmd_make_tx()
{
    const char* wdir = "/tmp/test_kyk_cmd_wallet_make_tx";
    struct kyk_wallet* wallet = NULL;
    struct kyk_block* new_blk = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    long double btc_num = 1.0;
    struct kyk_block* blk = NULL;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_wallet_make_tx: kyk_setup_wallet failed");

    res = kyk_wallet_make_coinbase_block(&blk, wallet);

    res = kyk_wallet_cmd_make_tx(&new_blk, wallet, btc_num, btc_addr);
    mu_assert(res == 0, "Failed to test_kyk_wallet_make_tx");

    return NULL;

error:

    return "Failed to test_kyk_wallet_cmd_make_tx";
}

char* test_kyk_spv_wallet_make_tx()
{
    const char* wdir = "/tmp/test_kyk_spv_wallet_make_tx";
    struct kyk_wallet* wallet = NULL;
    struct kyk_block* blk = NULL;
    const char* btc_addr = "1KuA5hsQwSc475WGdE9bVW29Ez2FVzb2Vj";
    struct kyk_tx* tx = NULL;
    long double btc_num = 1.0;
    int res = -1;

    res = kyk_setup_wallet(&wallet, wdir);
    check(res == 0, "Failed to test_kyk_spv_wallet_make_tx: kyk_setup_wallet failed");

    res = kyk_wallet_make_coinbase_block(&blk, wallet);

    res = kyk_spv_wallet_make_tx(&tx, wallet, btc_num, btc_addr);
    mu_assert(res == 0, "Failed to test_kyk_spv_wallet_make_tx");

    return NULL;

error:

    return "Failed to test_kyk_spv_wallet_make_tx";

}



char* all_tests()
{
    mu_suite_start();
    mu_run_test(test_kyk_new_wallet);
    mu_run_test(test_kyk_setup_wallet);
    mu_run_test(test_kyk_open_wallet);
    mu_run_test(test_kyk_create_wallet_key);
    mu_run_test(test_kyk_wallet_check_config);
    mu_run_test(test_kyk_wallet_add_address);
    mu_run_test(test_kyk_save_blk_header_chain);
    mu_run_test(test_kyk_load_blk_header_chain);
    mu_run_test(test_kyk_wallet_get_pubkey);
    mu_run_test(test_kyk_wallet_save_block);
    mu_run_test(test_kyk_load_utxo_chain);
    mu_run_test(test_kyk_wallet_save_utxo_chain);
    mu_run_test(test_kyk_load_utxo_chain_from_chainfile_buf);
    mu_run_test(test2_kyk_load_utxo_chain_from_chainfile_buf);
    mu_run_test(test_kyk_wallet_query_value_by_addr);
    mu_run_test(test_kyk_wallet_load_addr_list);
    mu_run_test(test_kyk_wallet_load_key_list);
    mu_run_test(test_kyk_wallet_cmd_make_tx);
    mu_run_test(test2_kyk_wallet_make_tx);
    mu_run_test(test3_kyk_wallet_make_tx);
    mu_run_test(test_kyk_spv_wallet_make_tx);

    return NULL;
}

MU_RUN_TESTS(all_tests);
