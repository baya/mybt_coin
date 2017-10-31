#ifndef KYK_LDB_H__
#define KYK_LDB_H__

#include <leveldb/c.h>

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
    }                                           \

extern const uint32_t BLOCK_HAVE_MASK;

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


void kyk_init_store_db(struct kyk_block_db *blk_db, char *path);
void kyk_free_block_db(struct kyk_block_db *blk_db);
void kyk_free_db_key(struct db_key *key);
void build_db_key(struct db_key *key, const char flag, char *src, size_t len);
size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);
size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);
size_t read_varint64(const uint8_t *buf, size_t len, uint64_t *val);
size_t pack_varint(uint8_t *buf, uint32_t n);

#endif
