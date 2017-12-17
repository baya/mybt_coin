#include <stdio.h>
#include <stdlib.h>
#include <leveldb/c.h>
#include <string.h>

#include "kyk_block.h"
#include "kyk_ldb.h"
#include "kyk_utils.h"
#include "dbg.h"

//! Unused.
/* const uint32_t BLOCK_VALID_UNKNOWN      =    0; */

/* //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future */
/* const uint32_t    BLOCK_VALID_HEADER       =    1; */

/* //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents */
/* //! are also at least TREE. */
/* const uint32_t    BLOCK_VALID_TREE         =    2; */

/* /\** */
/*  * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids, */
/*  * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all */
/*  * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set. */
/*  *\/ */
/* const uint32_t    BLOCK_VALID_TRANSACTIONS =    3; */

/* //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30. */
/* //! Implies all parents are also at least CHAIN. */
/* const uint32_t    BLOCK_VALID_CHAIN        =    4; */

/* //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS. */
/* const uint32_t    BLOCK_VALID_SCRIPTS      =    5; */

/* //! All validity bits. */
/* const uint32_t    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS | */
/*     BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS; */

const uint32_t    BLOCK_HAVE_DATA          =    8; //!< full block available in blk*.dat
const uint32_t    BLOCK_HAVE_UNDO          =   16; //!< undo data available in rev*.dat
const uint32_t    BLOCK_HAVE_MASK          =   8 | 16;

/* const uint32_t    BLOCK_FAILED_VALID       =   32; //!< stage after last reached validness failed */
/* const uint32_t    BLOCK_FAILED_CHILD       =   64; //!< descends from failed block */
/* const uint32_t    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD; */

/* const uint32_t    BLOCK_OPT_WITNESS       =   128; //!< block data in blk*.data was received with a witness-enforcing client */


int kyk_init_store_db(struct kyk_block_db *blk_db, char *path)
{
    check(blk_db, "Failed to kyk_init_store_db: blk_db is NULL");
    check(path, "Failed to kyk_init_store_db: path is NULL");
    
    blk_db -> errptr = NULL;
    /* blk_db -> path = malloc(sizeof(char) * (strlen(path) + 1)); */
    /* blk_db -> path = memcpy(blk_db -> path, path, strlen(path) + 1); */
    blk_db -> path = kyk_strdup(path);
    check(blk_db -> path, "Failed to kyk_init_store_db: blk_db -> path kyk_strdup failed");
    
    blk_db -> db_opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(blk_db -> db_opts, 1);
    blk_db -> db = leveldb_open(blk_db -> db_opts, blk_db -> path, &blk_db -> errptr);
    blk_db -> rd_opts = leveldb_readoptions_create();
    blk_db -> wr_opts = leveldb_writeoptions_create();

    return 0;

error:

    return -1;
}

void kyk_free_block_db(struct kyk_block_db *blk_db)
{
    if(blk_db -> path) free(blk_db -> path);
    if(blk_db -> db_opts) leveldb_options_destroy(blk_db -> db_opts);
    if(blk_db -> rd_opts) leveldb_readoptions_destroy(blk_db -> rd_opts);
    if(blk_db -> wr_opts) leveldb_writeoptions_destroy(blk_db -> wr_opts);
    if(blk_db -> db) leveldb_close(blk_db -> db);
}

void kyk_free_db_key(struct db_key *key)
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

void kyk_free_bval(struct kyk_bkey_val *bval)
{
    if(bval -> blk_hd) free(bval -> blk_hd);
    free(bval);
}

void kyk_print_bval(struct kyk_bkey_val *bval)
{
    struct kyk_blk_header* hd = NULL;
    hd = bval -> blk_hd;
    
    printf("wVersion: %d\n", bval -> wVersion);
    printf("nHeight:  %d\n", bval -> nHeight);
    printf("nStatus:  %d\n", bval -> nStatus);
    printf("nTx:      %d\n", bval -> nTx);
    printf("nFile:    %d\n", bval -> nFile);
    printf("nDataPos: %d\n", bval -> nDataPos);
    printf("nUndoPos: %d\n", bval -> nUndoPos);
    printf("Following is Block Header:\n");
    printf("nVersion: %d\n", hd -> version);
    kyk_print_hex("PrevHash ", hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    kyk_print_hex("hashMerkleRoot ", hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    printf("nTime:    %d\n", hd -> tts);
    printf("nBits:    %x\n", hd -> bts);
    printf("nNonce:   %d\n", hd -> nonce);

}

