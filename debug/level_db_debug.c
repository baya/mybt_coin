#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "dbg.h"
#include "kyk_utils.h"

int main()
{
    leveldb_t *db;
    leveldb_options_t *dbopt = leveldb_options_create();
    leveldb_options_set_create_if_missing(dbopt, 1);
    char *errptr = NULL;
    char *db_path = "/Users/jim/workspace/bitcoin-block-data/blocks/index";
    db = leveldb_open(dbopt, db_path, &errptr);
    if (errptr != NULL)
    {
        printf("open error: %s\n", errptr);
    }
    leveldb_readoptions_t *rdopt = leveldb_readoptions_create();
    char *bkey = "62000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    char *value;
    size_t valen = 0;
    value = leveldb_get(db, rdopt, bkey, 33, &valen, &errptr);
    check(errptr == NULL, "failed to get value");
    printf("get value: %s\n", value);

    leveldb_writeoptions_t *wrtopt = leveldb_writeoptions_create();
    leveldb_put(db, wrtopt, "abc", 3, "123", 3, &errptr);
    value = leveldb_get(db, rdopt, "abc", 3, &valen, &errptr);
    printf("get value: %s, len: %zu\n", value, valen);

    leveldb_readoptions_t* readopts = NULL;
    leveldb_iterator_t *iter = NULL;

    readopts = leveldb_readoptions_create();
    leveldb_readoptions_set_verify_checksums(readopts, 1);
    leveldb_readoptions_set_fill_cache(readopts, 0);

    iter = leveldb_create_iterator(db, readopts);
    leveldb_iter_seek_to_first(iter);

    while (leveldb_iter_valid(iter)) {
	const char *key;
	const char *val;
	size_t klen;
	size_t vlen;

	key = leveldb_iter_key(iter, &klen);
	val = leveldb_iter_value(iter, &vlen);

	
	//printf("k=%s vlen=%zu\n", key, vlen);
        kyk_print_hex("Key ", (uint8_t *)key, klen);
	kyk_print_hex("Value ", (uint8_t *)val, vlen);

	leveldb_iter_next(iter);
    }

    leveldb_readoptions_destroy(readopts);
    leveldb_iter_destroy(iter);

    leveldb_readoptions_destroy(rdopt);
    leveldb_writeoptions_destroy(wrtopt);
    leveldb_options_destroy(dbopt);
    leveldb_close(db);
    leveldb_free(db);
    return 0;
error:
    if(db) leveldb_close(db);
    if(db) leveldb_free(db);
    return -1;
}
