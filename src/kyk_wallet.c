#include "kyk_wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_utils.h"
#include "gens_block.h"
#include "block_store.h"
#include "kyk_ldb.h"
#include "dbg.h"

#define IDX_DB_NAME "index"

struct kyk_wallet {
    char *wdir;
    struct kyk_block_db* blk_index_db;
};

struct kyk_wallet* kyk_init_wallet(char *wdir)
{
    struct kyk_wallet* wallet = malloc(sizeof(struct kyk_wallet));
    struct kyk_block_db* blk_idx_db = malloc(sizeof(struct kyk_block_db));
    char *idx_db_path = NULL;
    wallet -> wdir = malloc(strlen(wdir) + 1);
    
    strncpy(wallet -> wdir, wdir, strlen(wdir) + 1);
    wallet -> blk_index_db = blk_idx_db;
    idx_db_path = kyk_pth_concat(wallet -> wdir, IDX_DB_NAME);
    kyk_init_store_db(wallet -> blk_index_db, idx_db_path);
    check(wallet -> blk_index_db -> errptr == NULL, "failed to init block index db");

    if(idx_db_path) free(idx_db_path);
    return wallet;
    
error:
    if(idx_db_path) free(idx_db_path);
    return NULL;
}

void kyk_destroy_wallet(struct kyk_wallet* wallet)
{
    if(wallet -> wdir) free(wallet -> wdir);
    if(wallet -> blk_index_db) kyk_free_block_db(wallet -> blk_index_db);
}


