#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "kyk_difficulty.h"
#include "mu_unit.h"

char* test_kyk_bts2dlt()
{
    /* bits of Gens block: https://webbtc.com/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json*/
    uint32_t bts = 486604799;

    /* bits of Block: https://blockchain.info/block-height/346752 */
    uint32_t bts2 = 404172480;
    uint64_t exp_dlt2 = 47427554951;

    /* bits of Block#381024 https://blockchain.info/block-height/381024 */
    uint32_t bts3 = 403810644;
    uint64_t exp_dlt3 = 62253982450;

    /* bits of Block#498064 https://blockchain.info/block-height/498064 */
    uint32_t bts4 = 402698477;
    uint64_t exp_dlt4 = 1590896927259;
    
    uint64_t dlt = 0;

    dlt = kyk_bts2dlt(bts);
    mu_assert(dlt == 1, "Failed to test_kyk_bts2dlt");

    dlt = kyk_bts2dlt(bts2);
    mu_assert(dlt == exp_dlt2, "Failed to test_kyk_bts2dlt");

    dlt = kyk_bts2dlt(bts3);
    mu_assert(dlt == exp_dlt3, "Failed to test_kyk_bts2dlt");

    dlt = kyk_bts2dlt(bts4);
    mu_assert(dlt == exp_dlt4, "Failed to test_kyk_bts2dlt");
    
    return NULL;
}

char* test_kyk_bts2target()
{
    /* bits of Gens block: https://webbtc.com/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json*/
    uint32_t bts = 486604799;
    mpz_t target, hs;
    uint8_t digest[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68,
	0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
	0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1,
	0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f
    };

    mpz_init(target);
    mpz_set_ui(target, 0);

    mpz_init(hs);
    mpz_set_ui(hs, 0);

    kyk_bts2target(bts, target);

    mpz_import(hs, sizeof(digest), 1, 1, 1, 0, digest);

    mu_assert(mpz_cmp(hs, target) <= 0, "Failed to test_kyk_bts2target");

    mpz_clear(target);
    mpz_clear(hs);

    return NULL;
}

char* test_kyk_dlt2target()
{
    /* difficulty of Gens block: https://webbtc.com/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json*/
    uint32_t dlt = 1;
    mpz_t target;
    mpz_t expect_target;

    mpz_init(target);
    mpz_init(expect_target);

    /* The big number 26959535291011309493156476344723991336010898738574164086137773096960 is eq to DLT1_TARGET_HEX_STR */
    mpz_set_str(expect_target, "26959535291011309493156476344723991336010898738574164086137773096960", 10);
    /* mpz_set_str(expect_target, DLT1_TARGET_HEX_STR, 0); */
    kyk_dlt2target(dlt, target);

    mu_assert(mpz_cmp(target, expect_target) == 0, "Failed to test_kyk_dlt2target");

    mpz_clear(target);
    mpz_clear(expect_target);
    
    return NULL;
}

char* test2_kyk_dlt2target()
{
    /* block#346752 https://blockchain.info/block-height/346752*/
    uint64_t dlt = 47427554951;
    uint8_t blk_hash[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0d, 0xe2, 0xec, 0x3c, 0x68, 0x55, 0xa2, 0xc2,
	0x01, 0x60, 0xb6, 0x69, 0x3d, 0x63, 0xd1, 0xa0,
	0xb7, 0x74, 0xca, 0x96, 0x30, 0xb6, 0x92, 0xbc
    };
    mpz_t target, hs;

    mpz_init(target);
    mpz_init(hs);

    mpz_import(hs, sizeof(blk_hash), 1, 1, 1, 0, blk_hash);
    kyk_dlt2target(dlt, target);
    mu_assert(mpz_cmp(hs, target) <= 0, "Failed to test2_kyk_dlt2target");

    mpz_clear(target);
    mpz_clear(hs);
    
    return NULL;
}


char* all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_bts2dlt);
    mu_run_test(test_kyk_bts2target);
    mu_run_test(test_kyk_dlt2target);
    mu_run_test(test2_kyk_dlt2target);

    return NULL;
}

MU_RUN_TESTS(all_tests);
