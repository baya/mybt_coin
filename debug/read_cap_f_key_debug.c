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
/* static const char DB_COINS = 'c'; */
/* static const char DB_BLOCK_FILES = 'f'; */
/* static const char DB_TXINDEX = 't'; */
/* static const char DB_BLOCK_INDEX = 'b'; */

/* static const char DB_BEST_BLOCK = 'B'; */
/* static const char DB_HEAD_BLOCKS = 'H'; */
static const char DB_FLAG = 'F';
/* static const char DB_REINDEX_FLAG = 'R'; */
/* static const char DB_LAST_BLOCK = 'l'; */


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
void build_cap_f_key(struct db_key *key, char *src, size_t len);
void free_db_key(struct db_key *key);

int main()
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = "/tmp/bitcoin-block-data/blocks/index";
    leveldb_readoptions_t *read_opts = NULL;
    struct db_key Fkey;
    char *value = NULL;
    size_t vlen = 0;
    char *src = "\7txindex";

    build_cap_f_key(&Fkey, src, strlen(src));

    kyk_print_hex("Fkey ", (uint8_t *)Fkey.body, Fkey.len);

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)Fkey.body, Fkey.len, &vlen, &errptr);
    check(errptr == NULL, "get value error: %s", errptr);
    kyk_print_hex("raw value ", (uint8_t *)value, vlen);
    if(value[0] == '1'){
	printf("txindex: true\n");
    } else {
	printf("txindex: false\n");
    }
    


    free_db_key(&Fkey);
    leveldb_close(db);

    return 0;

error:
    free_db_key(&Fkey);
    if(db) leveldb_close(db);
    return -1;
    

}

void free_db_key(struct db_key *key)
{
    if(key -> src) free(key -> src);
    if(key -> body) free(key -> body);
}

void build_cap_f_key(struct db_key *key, char *src, size_t len)
{
    key -> flag = DB_FLAG;    
    key -> src = malloc(len * sizeof(char));
    memcpy(key -> src, src, len);
    key -> body = malloc((len + 1) * sizeof(char));
    key -> body[0] = DB_FLAG;
    memcpy(key -> body + 1, key -> src, len);
    key -> len = len + 1;
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
