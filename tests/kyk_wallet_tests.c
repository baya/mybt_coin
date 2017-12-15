#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_data.h"
#include "kyk_utxo.h"
#include "kyk_wallet.h"
#include "kyk_utils.h"
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
    struct kyk_wallet* wallet = NULL;

    wallet = kyk_open_wallet(wdir);
    mu_assert(wallet, "Failed to test_kyk_open_wallet");
    
    return NULL;
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
    // printf("btc address: %s\n", wkey -> btc_addr);
    
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

    res = kyk_save_blk_header_chain(wallet, hd_chain);
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

    res = kyk_deseri_block(&blk, BLOCK_BUF, NULL);
    check(res == 0, "Failed to test_kyk_wallet_save_block: kyk_deseri_block failed");

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

    return NULL;
}

MU_RUN_TESTS(all_tests);
