#ifndef KYK_LDB_H__

#include <leveldb/c.h>

#define KYK_LDB_H__

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

struct kyk_block_db {
    char                   *path;
    leveldb_t              *db;
    leveldb_options_t      *db_opts;
    leveldb_readoptions_t  *rd_opts;
    leveldb_writeoptions_t *wr_opts;
    char *errptr;
};

struct kyk_bkey_val{
    int wVersion;
    int nHeight;
    uint32_t nStatus;
    unsigned int nTx;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    struct kyk_blk_header *blk_hd;
};

void kyk_init_store_db(struct kyk_block_db *blk_db, char *path)
{
    blk_db -> errptr = NULL;
    blk_db -> path = malloc(sizeof(char) * (strlen(path) + 1));
    blk_db -> db_opts = leveldb_options_create();
    blk_db -> db = leveldb_open(blk_db -> db_opts, blk_db -> path, &blk_db -> errptr);
    blk_db -> rd_opts = leveldb_readoptions_create();
    blk_db -> wr_opts = leveldb_writeoptions_create();
}

void kyk_free_block_db(struct kyk_block_db *blk_db)
{
    if(blk_db -> path) free(blk_db -> path);
    if(blk_db -> db_opts) leveldb_options_destroy(blk_db -> db_opts);
    if(blk_db -> rd_opts) leveldb_readoptions_destroy(blk_db -> rd_opts);
    if(blk_db -> wr_opts) leveldb_writeoptions_destroy(blk_db -> wr_opts);
    if(blk_db -> db) leveldb_close(blk_db -> db);
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


size_t pack_varint(uint8_t *buf, uint32_t n)
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


#endif
