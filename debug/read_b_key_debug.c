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
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *read_opts = NULL;
    const uint8_t b_key[33];
    char *value = NULL;
    size_t vlen = 0;

    hexstr_to_bytes("62000039fc87f911322f7736332364f5141ca6d156aa2056480000000000000000", b_key, sizeof(b_key));
    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, b_key, sizeof(b_key), &vlen, &errptr);
    kyk_print_hex("value ", value, vlen);
    /* iter = leveldb_create_iterator(db, read_opts);          */
    /* leveldb_iter_seek_to_first(iter); */

    /* int i = 0; */
    /* char r_key[100]; */
    /* while (leveldb_iter_valid(iter)) { */
    /* 	i++; */
    /* 	const char *key; */
    /* 	const char *val;	 */
    /* 	size_t klen; */
    /* 	size_t vlen; */

    /* 	key = leveldb_iter_key(iter, &klen); */
    /* 	val = leveldb_iter_value(iter, &vlen); */
	

    /* 	//printf("key=%s value=%s\n", key, val); */
    /* 	kyk_print_hex("key ", (const uint8_t *)key, klen); */
    /* 	kyk_print_hex("val ", (const uint8_t *)val, vlen); */
    /* 	//kyk_reverse(key, klen); */
    /* 	kyk_reverse_pack_chars((unsigned char*)r_key, (const unsigned char*)key, klen); */
    /* 	kyk_print_hex("reversed key", r_key, klen); */
	

    /* 	leveldb_iter_next(iter); */
    /* 	if(i >= 10){ */
    /* 	    break; */
    /* 	} */
    /* } */



    leveldb_close(db);
    
    return 0;
    
error:
    if(db) leveldb_close(db);
    return -1;
}
