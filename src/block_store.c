#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>


#include "kyk_block.h"
#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_address.h"
#include "kyk_mkl_tree.h"
#include "kyk_ser.h"
#include "kyk_difficulty.h"
#include "kyk_hash_nonce.h"
#include "kyk_pem.h"
#include "kyk_ldb.h"
#include "kyk_buff.h"

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


void kyk_store_block(struct kyk_block_db* blk_db, struct kyk_block *blk)
{
    struct db_key key;
    build_b_key(&key, blk);
    leveldb_put(blk_db -> db,
		blk_db -> rd_opts,
		key -> body,
		key -> len,
		
	)
}

void build_b_key(struct db_key *key, struct kyk_block *blk)
{
    uint8_t src[32] = blk -> hd -> blk_hash;
    kyk_reverse(src, sizeof(src));
    build_db_key(key, DB_BLOCK_INDEX, sizeof(src));
}

struct kyk_buff* build_b_value(struct kyk_bkey_val* bval)
{
    struct kyk_buff* buf = malloc(sizeof(struct kyk_buff));
    uint8_t tmp[1000];
    uint8_t *tptr = tmp;
    size_t ofst = 0;

    ofst = pack_varint(tptr, bval -> wWersion);
    tptr += ofst;
    ofst = pack_varint(tptr, bval -> nHeight);
    tptr += ofst;
    ofst = pack_varint(tptr, bval -> nStatus);
    tptr += ofst

    return buf;
}

size_t kyk_ser_bval(uint8_t *buf, struct kyk_bkey_val *bval)
{
    uint8_t *buf_start = buf;
    size_t len = 0;
    
    ofst = pack_varint(buf, bval -> wWersion);
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

    ofst = kyk_seri_blk_hd(buf, bval -> hd);
    buf += ofst;

    len = buf - buf_start;

    return len;
}

