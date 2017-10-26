#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "dbg.h"

int main()
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = "/tmp/bitcoin-block-data/blocks/index";
    leveldb_readoptions_t *read_opts = NULL;
    const uint8_t b_key[33];
    char *value = NULL;
    size_t vlen = 0;

    hexstr_to_bytes("62000039fc87f911322f7736332364f5141ca6d156aa2056480000000000000000", (unsigned char*)b_key, sizeof(b_key));
    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)b_key, sizeof(b_key), &vlen, &errptr);
    kyk_print_hex("value ", (unsigned char*)value, vlen);


    leveldb_close(db);
    
    return 0;
    
error:
    if(db) leveldb_close(db);
    return -1;
}
