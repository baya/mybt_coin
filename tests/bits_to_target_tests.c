#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>

#include "kyk_utils.h"
#include "kyk_difficulty.h"
#include "mu_unit.h"


/*
 * 0x1b0404cb
 * 0x0404cb * 2**(8*(0x1b - 3)) = 0x00000000000404CB000000000000000000000000000000000000000000000000
 */
char *test_blk_difficulty()
{
    
    uint32_t bts = 0x1d00ffff;
    uint32_t dlt;
    mpz_t tg, exp_tg;
    mpz_init(tg);
    mpz_init(exp_tg);
    mpz_set_ui(tg, 0);
    mpz_set_str(exp_tg, "0xffff0000000000000000000000000000000000000000000000000000", 0);

    kyk_bts2target(bts, tg);
    dlt = kyk_bts2dlt(bts);
    /* gmp_printf("0x%02x => target is: 0x%Zx\n", bts, tg); */
    /* gmp_printf("0x%02x => difficulty is: %u\n", bts, dlt); */
    
    mu_assert(dlt == 1, "Failed to get the correct difficulty");
    mu_assert(mpz_cmp(tg, exp_tg) == 0, "Failed to get the correct target");

    bts = 0x1b0404cb;
    kyk_bts2target(bts, tg);
    dlt = kyk_bts2dlt(bts);
    mpz_set_str(exp_tg, "0x404cb000000000000000000000000000000000000000000000000", 0);
    mu_assert(dlt == 16308, "Failed to get the correct difficulty");
    mu_assert(mpz_cmp(tg, exp_tg) == 0, "Failed to get the correct target");


    return NULL;

}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_blk_difficulty);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
