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
#include "kyk_blk_file.h"
#include "dbg.h"
#include "kyk_ser.h"
#include "kyk_buff.h"


#define IDX_DB_NAME "index"

struct kyk_wallet {
    char *wdir;
    struct kyk_block_db* blk_index_db;
};

static void set_init_bval(struct kyk_bkey_val *bval, struct kyk_block* blk);
static int load_init_data_to_wallet(struct kyk_wallet *wallet);

struct kyk_wallet* kyk_init_wallet(char *wdir)
{
    struct kyk_wallet* wallet = malloc(sizeof(struct kyk_wallet));
    struct kyk_block_db* blk_idx_db = malloc(sizeof(struct kyk_block_db));
    char *idx_db_path = NULL;
    int res = 0;
    wallet -> wdir = malloc(strlen(wdir) + 1);
    
    strncpy(wallet -> wdir, wdir, strlen(wdir) + 1);
    wallet -> blk_index_db = blk_idx_db;
    idx_db_path = kyk_pth_concat(wallet -> wdir, IDX_DB_NAME);
    kyk_init_store_db(wallet -> blk_index_db, idx_db_path);
    check(wallet -> blk_index_db -> errptr == NULL, "failed to init block index db");
    res = load_init_data_to_wallet(wallet);
    check(res > 0, "failed to init wallet");
    
    if(idx_db_path) free(idx_db_path);
    return wallet;
    
error:
    if(idx_db_path) free(idx_db_path);
    return NULL;
}

struct kyk_wallet* kyk_open_wallet(char *wdir)
{
    struct kyk_wallet* wallet = malloc(sizeof(struct kyk_wallet));
    struct kyk_block_db* blk_idx_db = malloc(sizeof(struct kyk_block_db));
    char *idx_db_path = NULL;
    wallet -> wdir = malloc(strlen(wdir) + 1);
    
    strncpy(wallet -> wdir, wdir, strlen(wdir) + 1);
    wallet -> blk_index_db = blk_idx_db;
    idx_db_path = kyk_pth_concat(wallet -> wdir, IDX_DB_NAME);
    kyk_init_store_db(wallet -> blk_index_db, idx_db_path);
    check(wallet -> blk_index_db -> errptr == NULL, "failed to open block index db");
    
    if(idx_db_path) free(idx_db_path);
    return wallet;
    
error:
    if(idx_db_path) free(idx_db_path);
    return NULL;
}

struct kyk_bkey_val* w_get_block(const struct kyk_wallet* wallet, const char* blk_hash_str, char **errptr)
{
    struct kyk_block* blk;
    struct kyk_bkey_val* bval = NULL;
    char blk_hash[32];
    size_t len = strlen(blk_hash_str);
    check(len == 64, "invalid block hash");

    kyk_parse_hex(blk_hash, blk_hash_str);
    bval = kyk_read_block(wallet -> blk_index_db, blk_hash, errptr);

    return bval;
error:
    if(bval) kyk_free_bval(bval);
    return NULL;
}

void kyk_destroy_wallet(struct kyk_wallet* wallet)
{
    if(wallet -> wdir) free(wallet -> wdir);
    if(wallet -> blk_index_db) kyk_free_block_db(wallet -> blk_index_db);
}

int load_init_data_to_wallet(struct kyk_wallet *wallet)
{
    struct kyk_block *blk = NULL;
    struct kyk_bkey_val bval;
    int res = 1;
    char *errptr = NULL;
    
    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");
    set_init_bval(&bval, blk);
    kyk_store_block(wallet -> blk_index_db, &bval, &errptr);
    check(errptr == NULL, "failed to store b key value");

    if(blk) kyk_free_block(blk);
    return res;

error:
    if(blk) kyk_free_block(blk);
    return -1;
}

void set_init_bval(struct kyk_bkey_val *bval, struct kyk_block* blk)
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

int kyk_save_blk_to_file(struct kyk_blk_file* blk_file,
			   const struct kyk_block* blk
    )
{
    struct kyk_buff* buf = NULL;
    size_t len = 0;

    buf = create_kyk_buff(1000);
    check(buf != NULL, "failed to create kyk buff");
    len = kyk_ser_blk_for_file(buf, blk);
    
    off_t currpos;
    currpos = lseek(blk_file -> fp, 0, SEEK_END);
    check(currpos > -1, "failed to lseek file");

    return 1;
error:
    return -1;
}

