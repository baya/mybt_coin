#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kyk_utils.h"
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

void set_block_test_dir()
{
    const char* dir1 = "/tmp/mybt_coin";
    const char* dir2 = "/tmp/mybt_coin/testblocks";
    
    if(kyk_detect_dir(dir1) != 1){
	mkdir(dir1, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    if(kyk_detect_dir(dir2) != 1){
	mkdir(dir2, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
}

char* test_store_block()
{
    struct kyk_block* blk;
    struct kyk_block_db blk_db;
    char* errmsg = "failed to test store block";
    char *errptr = NULL;
    struct kyk_bkey_val bval;

    set_block_test_dir();

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

char* test_read_block()
{
    struct kyk_block* blk;
    struct kyk_block_db blk_db;
    char* errmsg = "failed to test read block";
    char* errptr = NULL;
    uint8_t blk_hash[32];
    struct kyk_bkey_val* bval = NULL;

    set_block_test_dir();

    kyk_init_store_db(&blk_db, BLOCK_TEST_INDEX_DB);
    check(blk_db.errptr == NULL, "failed to init block db %s", blk_db.errptr);

    blk = make_gens_block();
    kyk_parse_hex(blk_hash, "0000876c9ef8c1f8b2a3012ec1bdea7296f95ae21681799f8adf967f548bf8f3");
    bval = kyk_read_block(&blk_db, (char *)blk_hash, &errptr);
    check(errptr == NULL, "failed to test read b key value");

    mu_assert(bval != NULL, "failed to test read block");

    mu_assert(bval -> wVersion == 1, "failed to get the correct wVersion");
    mu_assert(bval -> nHeight == 0, "failed to get the correct nHeight");
    mu_assert(bval -> nStatus == BLOCK_HAVE_MASK, "failed to get the correct nStatus");
    mu_assert(bval -> nTx == 1, "failed to get the correct nTx");
    mu_assert(bval -> nFile == 0, "failed to get the correct nFile");
    mu_assert(bval -> nDataPos == 8, "failed to get the correct nDataPos");
    mu_assert(bval -> nUndoPos == 0, "failed to get the correct nUndoPos");
    mu_assert(kyk_digest_eq(bval -> blk_hd -> mrk_root_hash, blk -> hd -> mrk_root_hash, 32), "failed to get the correct block header");

    if(bval) kyk_free_bval(bval);
    kyk_free_block_db(&blk_db);
    return NULL;

error:
    if(bval) kyk_free_bval(bval);
    kyk_free_block_db(&blk_db);
    return errmsg;


}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_store_block);
    mu_run_test(test_read_block)
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

