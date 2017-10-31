#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "block_store.h"

static const char DB_COIN = 'C';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';
static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

void build_b_key(struct db_key *key, struct kyk_blk_header *blk_hd);
size_t kyk_ser_bval(uint8_t *buf, struct kyk_bkey_val *bval);
struct kyk_buff* build_b_value(struct kyk_bkey_val* bval);


void kyk_store_block(struct kyk_block_db* blk_db,
		     struct kyk_bkey_val* bval,
		     char **errptr
    )
{
    struct db_key key;
    struct kyk_buff *buf = NULL;
    build_b_key(&key, bval -> blk_hd);
    buf = build_b_value(bval);
    leveldb_put(blk_db -> db,
		blk_db -> wr_opts,
		key.body,
		key.len,
		(char *)buf -> base,
		buf -> len,
		errptr
	);

    free_db_key(&key);
    if(buf) free_kyk_buff(buf);
}

void build_b_key(struct db_key *key, struct kyk_blk_header* blk_hd)
{
    uint8_t src[32];
    memcpy(src, blk_hd -> blk_hash, sizeof(src));
    kyk_reverse(src, sizeof(src));
    build_db_key(key, DB_BLOCK_INDEX, (char *)src, sizeof(src));
}

struct kyk_buff* build_b_value(struct kyk_bkey_val* bval)
{
    struct kyk_buff* buf = malloc(sizeof(struct kyk_buff));
    uint8_t tmp[1000];

    buf -> len = 0;
    buf -> idx = 0;

    buf -> len = kyk_ser_bval(tmp, bval);
    buf -> base = malloc(buf -> len);
    memcpy(buf -> base, tmp, buf -> len);

    return buf;
}

size_t kyk_ser_bval(uint8_t *buf, struct kyk_bkey_val *bval)
{
    uint8_t *buf_start = buf;
    size_t len = 0;
    size_t ofst = 0;
    
    ofst = pack_varint(buf, bval -> wVersion);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nHeight);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nStatus);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nTx);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nFile);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nDataPos);
    buf += ofst;
    ofst = pack_varint(buf, bval -> nUndoPos);
    buf += ofst;

    ofst = kyk_seri_blk_hd(buf, bval -> blk_hd);
    buf += ofst;

    len = buf - buf_start;

    return len;
}

