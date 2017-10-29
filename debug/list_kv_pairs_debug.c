#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "dbg.h"

#define INDEX_DB_PATH "/tmp/bitcoin-block-data/blocks/index"
#define UTXO_DB_PATH "/tmp/bitcoin-block-data/chainstate"

const static char INDEX_KEY_FLAGS[] = {'b', 'f', 'l', 'R', 't'};
const static char UTXO_KEY_FLAGS[] = {'c', 'C', 'B'};

char *get_db_path(char ktype);

int main(int argc, char *argv[])
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = NULL;
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *read_opts = NULL;
    char ktype = 'b';
    char c;
    int knum = 1;

    while ((c = getopt(argc, argv, "bflRFtcCBhn:")) != EOF) {
	switch (c) {
	case 'b':
	    ktype = 'b';
	    break;
	case 'f':
	    ktype = 'f';
	    break;
	case 'l':
	    ktype = 'l';
	    break;
	case 'R':
	    ktype = 'R';
	    break;
	case 'F':
	    ktype = 'F';
	    break;
	case 't':
	    ktype = 't';
	    break;
	case 'c':
	    ktype = 'c';
	    break;
	case 'C':
	    ktype = 'C';
	    break;
	case 'B':
	    ktype = 'B';
	    break;
	case 'n':
	    knum = atoi(optarg);
	    break;
	case 'h':
	default:
	    printf("listing option bflRFtcB\n");
	    return 1;
	}
    }

    db_path = get_db_path(ktype);
    printf("use %s\n", db_path);
    check(db_path != NULL, "don't find valid db path");

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    iter = leveldb_create_iterator(db, read_opts);
    leveldb_iter_seek_to_first(iter);

    int i = 0;
    char r_key[100];
    printf("listing `%c` key\n", ktype);
    while (leveldb_iter_valid(iter)) {
    	const char *key;
    	const char *val;
    	size_t klen;
    	size_t vlen;

    	key = leveldb_iter_key(iter, &klen);
    	val = leveldb_iter_value(iter, &vlen);


	//printf("get key %c\n", *key);
	if(key && (char)key[0] == ktype){
	    i++;
	    kyk_print_hex("key ", (const uint8_t *)key, klen);
	    kyk_print_hex("val ", (const uint8_t *)val, vlen);
	    if(ktype == 'b'){
		kyk_reverse_pack_chars((unsigned char*)r_key, (const unsigned char*)key, klen);
		kyk_print_hex("reversed key", (uint8_t *)r_key, klen);
	    }

	    if(i >= knum){
		break;
	    }
	}


    	leveldb_iter_next(iter);
    }


    leveldb_close(db);
    
    return 0;
    
error:
    if(db) leveldb_close(db);
    return -1;
}

char *get_db_path(char ktype)
{
    size_t i = 0;
    for(i = 0; i < sizeof(INDEX_KEY_FLAGS); i++){
	if(INDEX_KEY_FLAGS[i] == ktype){
	    return INDEX_DB_PATH;
	}
    }

    for(i = 0; i < sizeof(UTXO_KEY_FLAGS); i++){
	if(UTXO_KEY_FLAGS[i] == ktype){
	    return UTXO_DB_PATH;
	}
    }

    return NULL;
}
