#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "gens_block.h"
#include "mu_unit.h"

char *test_kyk_ser_blk()
{
    struct kyk_block* blk = NULL;
    struct kyk_buff* buf = NULL;
    char *errmsg = "failed to test kyk ser block";

    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");

    buf = create_kyk_buff(1000);
    check(buf != NULL, "failed to create kyk buff");

    kyk_ser_blk(buf, blk);

    mu_assert(buf -> idx == blk -> blk_size, "failed to get the correct block len");

    return NULL;

error:
    if(buf) free_kyk_buff(buf);
    if(blk) kyk_free_block(blk);
    return errmsg;
    
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_ser_blk);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
