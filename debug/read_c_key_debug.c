#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "basic_defs.h"
#include "dbg.h"
#include "beej_pack.h"

/* static const char DB_COIN = 'C'; */
static const char DB_COINS = 'c';
/* static const char DB_BLOCK_FILES = 'f'; */
/* static const char DB_TXINDEX = 't'; */
/* static const char DB_BLOCK_INDEX = 'b'; */

/* static const char DB_BEST_BLOCK = 'B'; */
/* static const char DB_HEAD_BLOCKS = 'H'; */
/* static const char DB_FLAG = 'F'; */
/* static const char DB_REINDEX_FLAG = 'R'; */
/* static const char DB_LAST_BLOCK = 'l'; */

#define INDEX_DB_PATH "/tmp/bitcoin-block-data/blocks/index"
#define UTXO_DB_PATH "/tmp/bitcoin-block-data/chainstate"

#define READ_VARINT_LOOP(N, I, LEN, BUF, VAL)	\
    while((I) < (LEN)) {			\
	unsigned char chData = *(BUF);		\
	BUF++;					\
        (N) = ((N) << 7) | (chData & 0x7F);	\
        if (chData & 0x80) {			\
	    (I)++;				\
            (N)++;				\
        } else {				\
	    *(VAL) = N;				\
	    (I)++;				\
            return (I);				\
        }					\
    }						\


struct db_key {
    char flag;
    char *src;
    char *body;
    size_t len;
};

size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);
size_t read_varint64(const uint8_t *buf, size_t len, uint64_t *val);
void build_db_key(struct db_key *key, const char flag, char *src, size_t len);
void free_db_key(struct db_key *key);

int main(int argc, char *argv[])
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = UTXO_DB_PATH;
    leveldb_readoptions_t *read_opts = NULL;
    struct db_key ckey;
    char *value = NULL;
    size_t vlen = 0;
    char *src = NULL;
    size_t src_len = 0;

    if(argc != 2){
	printf("please provide a Tx id such as 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\n");
	return -1;
    }

    src = (char *) kyk_alloc_hex(argv[1], &src_len);
    kyk_reverse((uint8_t *)src, src_len);

    build_db_key(&ckey, DB_COINS, src, strlen(src));

    kyk_print_hex("ckey ", (uint8_t *)ckey.body, ckey.len);

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)ckey.body, ckey.len, &vlen, &errptr);
    check(errptr == NULL, "get value error: %s", errptr);
    if(vlen > 0){
	kyk_print_hex("raw value ", (uint8_t *)value, vlen);
    } else {
	printf("No record Found\n");
    }
    


    free(src);
    free_db_key(&ckey);
    leveldb_close(db);

    return 0;

error:
    if(src) free(src);
    free_db_key(&ckey);
    if(db) leveldb_close(db);
    return -1;
    

}

void free_db_key(struct db_key *key)
{
    if(key -> src) free(key -> src);
    if(key -> body) free(key -> body);
}

void build_db_key(struct db_key *key, const char flag, char *src, size_t len)
{
    size_t klen = len + sizeof(flag);
    key -> flag = flag;    
    key -> src = malloc(len * sizeof(char));
    memcpy(key -> src, src, len);
    key -> body = malloc(klen * sizeof(char));
    key -> body[0] = flag;
    memcpy(key -> body + 1, key -> src, len);
    key -> len = klen;
}

size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val)
{
    uint32_t n = 0;
    
    size_t i = 0;

    READ_VARINT_LOOP(n, i, len, buf, val);

    return 0;
}

size_t read_varint64(const uint8_t *buf, size_t len, uint64_t *val)
{
    uint64_t n = 0;
    
    size_t i = 0;

    READ_VARINT_LOOP(n, i, len, buf, val);

    return 0;
}


size_t pack_varint(uint8_t *buf, int n)
{
    unsigned char tmp[(sizeof(n)*8+6)/7];
    int len=0;
    while(1) {
        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
        len++;
    }

    kyk_reverse_pack_chars(buf, tmp, len+1);

    return len+1;
}
