#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "gens_block.h"
#include "block_store.h"
#include "kyk_ldb.h"
#include "mu_unit.h"

#define BLOCK_TEST_INDEX_DB "/tmp/mybt_coin/testblocks/index"

void set_bval(struct kyk_bkey_val *bval, struct kyk_block* blk)
{
    bval -> wVersion = 1;
    bval -> nHeight = 0;
    bval -> nStatus = BLOCK_HAVE_MASK;
    bval -> nTx = 1;
    bval -> nFile = 0;
    bval -> nDataPos = 8;
    bval -> nUndoPos = 0;
    bval -> blk_hd = blk -> hd;
}

char* test_store_block()
{
    struct kyk_block* blk;
    struct kyk_block_db blk_db;
    char* errmsg = "failed to test store block";
    char *errptr = NULL;
    struct kyk_bkey_val bval;

    blk = make_gens_block();
    set_bval(&bval, blk);

    kyk_init_store_db(&blk_db, BLOCK_TEST_INDEX_DB);
    check(blk_db.errptr == NULL, "failed to open db");    

    kyk_store_block(&blk_db, &bval, &errptr);
    check(errptr == NULL, "failed to store block b key value");

    if(blk) kyk_free_block(blk);
    kyk_free_block_db(&blk_db);

    return NULL;
error:
    if(blk) kyk_free_block(blk);
    kyk_free_block_db(&blk_db);
    return errmsg;
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_store_block);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

