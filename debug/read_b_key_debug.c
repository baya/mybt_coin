#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "dbg.h"

int blk_hashstr_to_bkey(const char *hstr, uint8_t *bkey, size_t klen);

int main()
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = "/tmp/bitcoin-block-data/blocks/index";
    leveldb_readoptions_t *read_opts = NULL;
    uint8_t bkey[33];
    char *value = NULL;
    size_t vlen = 0;
    char *blk_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26";
    int res = 0;
    errno = 0;

    res = blk_hashstr_to_bkey(blk_hash, bkey, sizeof(bkey));
    check(res > -1, "failed to convert block hash to bkey");
    kyk_print_hex("bkey ", bkey, sizeof(bkey));

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)bkey, sizeof(bkey), &vlen, &errptr);
    kyk_print_hex("value ", (unsigned char*)value, vlen);


    leveldb_close(db);
    
    return 0;
    
error:
    if(db) leveldb_close(db);
    return -1;
}

int blk_hashstr_to_bkey(const char *hstr, uint8_t *bkey, size_t klen)
{
    char prefix = 'b';
    int res = 0;
    
    *bkey = prefix;
    bkey++;
    
    res = hexstr_to_bytes(hstr, bkey, klen - 1);
    check(res > -1, "failed to convert hex to bytes");
    kyk_reverse(bkey, klen - 1);

    return 0;

error:
    return -1;
    
}


