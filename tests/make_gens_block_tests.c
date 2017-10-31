#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "gens_block.h"
#include "mu_unit.h"

char *test_make_gens_block()
{
    struct kyk_block* blk;
    const char *err_msg = "failed to make gens block";

    blk = make_gens_block();

    uint8_t target_blk_hash[32];
    kyk_parse_hex(target_blk_hash, "0000876c9ef8c1f8b2a3012ec1bdea7296f95ae21681799f8adf967f548bf8f3");
    mu_assert(kyk_digest_eq(blk -> hd -> blk_hash, target_blk_hash, sizeof(target_blk_hash)), "failed to get the correct block hash");

    uint8_t target_mkl_rt[32];
    kyk_parse_hex(target_mkl_rt, "b76d27da4abf50387dd70f5d6cc7e4df1d54722631cbbfdd292463df77aa0dbd");
    mu_assert(kyk_digest_eq(blk -> hd -> mrk_root_hash, target_mkl_rt, sizeof(target_mkl_rt)), "failed to get the correct merkle root");
    
    kyk_free_block(blk);
    
    return NULL;

error:
    if(blk) kyk_free_block(blk);
    return err_msg;

}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_gens_block);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

