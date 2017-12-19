#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "test_data.h"
#include "kyk_block.h"
#include "kyk_validate.h"
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

    res = kyk_deseri_block(&blk, BTC_2_BLOCK_BUF, &check_size);
    check(res == 0, "Failed to test_kyk_validate_block: kyk_deseri_block failed");

    res = kyk_validate_block(hd_chain, blk);
    mu_assert(res == 0, "Failed to test_kyk_validate_block");
    
    return NULL;

error:
    
    return "Failed to test_kyk_validate_block";
}

char* test_kyk_validate_txin_script_sig()
{
    return NULL;
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_validate_blk_header);
    mu_run_test(test2_kyk_validate_blk_header);
    mu_run_test(test_kyk_validate_txin_script_sig);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
