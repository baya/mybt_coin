#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "basic_defs.h"
#include "dbg.h"
#include "beej_pack.h"


//! Unused.
const uint32_t BLOCK_VALID_UNKNOWN      =    0;

//! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
const uint32_t    BLOCK_VALID_HEADER       =    1;

//! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
//! are also at least TREE.
const uint32_t    BLOCK_VALID_TREE         =    2;

/**
 * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
 * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
 * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
 */
const uint32_t    BLOCK_VALID_TRANSACTIONS =    3;

//! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
//! Implies all parents are also at least CHAIN.
const uint32_t    BLOCK_VALID_CHAIN        =    4;

//! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
const uint32_t    BLOCK_VALID_SCRIPTS      =    5;

//! All validity bits.
const uint32_t    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
    BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS;

const uint32_t    BLOCK_HAVE_DATA          =    8; //!< full block available in blk*.dat
const uint32_t    BLOCK_HAVE_UNDO          =   16; //!< undo data available in rev*.dat
const uint32_t    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;

const uint32_t    BLOCK_FAILED_VALID       =   32; //!< stage after last reached validness failed
const uint32_t    BLOCK_FAILED_CHILD       =   64; //!< descends from failed block
const uint32_t    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD;

const uint32_t    BLOCK_OPT_WITNESS       =   128; //!< block data in blk*.data was received with a witness-enforcing client

/* #define BLOCK_TEST_INDEX_DB "/tmp/mybt_coin/testblocks/index" */
#define BLOCK_TEST_INDEX_DB "/tmp/bitcoin-block-data/blocks/index"

int blk_hashstr_to_bkey(const char *hstr, uint8_t *bkey, size_t klen);
size_t pack_varint(uint8_t *buf, int n);
size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);

int main(int argc, char *argv[])
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = BLOCK_TEST_INDEX_DB;
    leveldb_readoptions_t *read_opts = NULL;
    uint8_t bkey[33];
    char *value = NULL;
    char *valptr = NULL;
    size_t vlen = 0;
    //char *blk_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    //char *blk_hash = "0000000099c744455f58e6c6e98b671e1bf7f37346bfd4cf5d0274ad8ee660cb";
    if(argc != 2){
	printf("please provide a block hash, such as 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\n");
	return 1;
    }
    char *blk_hash = argv[1];
    int res = 0;
    errno = 0;
    
    // wallet version
    int wVersion = 0;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight = 0;

    //! Verification status of this block.
    uint32_t nStatus = 0;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx = 0;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile = 0;

     //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos = 0;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos = 0;

    //! block header
    int32_t nVersion;
    uint256 prevHash;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    
    res = blk_hashstr_to_bkey(blk_hash, bkey, sizeof(bkey));
    check(res > -1, "failed to convert block hash to bkey");
    kyk_print_hex("bkey ", bkey, sizeof(bkey));

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)bkey, sizeof(bkey), &vlen, &errptr);
    check(errptr == NULL, "get value error: %s", errptr);
    if(vlen <= 0){
	printf("Found no record\n");
	return -1;
    } 
    kyk_print_hex("raw value ", (unsigned char*)value, vlen);

    valptr = value;
    size_t ofst = 0;
    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&wVersion);
    valptr += ofst;
    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nHeight);
    valptr += ofst;
    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nStatus);
    valptr += ofst;

    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nTx);
    valptr += ofst;

    if(nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)){
	ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nFile);
	valptr += ofst;
    }
    
    if (nStatus & BLOCK_HAVE_DATA){
	ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nDataPos);
	valptr += ofst;
    }

    if (nStatus & BLOCK_HAVE_UNDO){
	ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nUndoPos);
	valptr += ofst;
    }


    beej_unpack((unsigned char *)valptr, "<l", &nVersion);
    valptr += sizeof(nVersion);
    
    kyk_reverse_pack_chars(prevHash.data, (unsigned char *)valptr, sizeof(prevHash.data));
    valptr += sizeof(prevHash.data);

    kyk_reverse_pack_chars(hashMerkleRoot.data, (unsigned char *)valptr, sizeof(hashMerkleRoot.data));
    valptr += sizeof(prevHash.data);

    beej_unpack((unsigned char *)valptr, "<L", &nTime);
    valptr += sizeof(nTime);

    beej_unpack((unsigned char *)valptr, "<L", &nBits);
    valptr += sizeof(nBits);

    beej_unpack((unsigned char *)valptr, "<L", &nNonce);
        
    printf("wVersion: %d\n", wVersion);
    printf("nHeight: %d\n", nHeight);
    printf("nStatus: %d\n",   nStatus);
    printf("nTx: %d\n",   nTx);
    printf("nFile: %d\n", nFile);
    printf("nDataPos: %d\n", nDataPos);
    printf("nUndoPos: %d\n", nUndoPos);

    printf("Following is Block Header:\n");
    printf("nVersion:%d\n", nVersion);
    kyk_print_hex("PrevHash ", prevHash.data, sizeof(prevHash.data));
    kyk_print_hex("hashMerkleRoot ", hashMerkleRoot.data, sizeof(hashMerkleRoot.data));
    printf("nTime:%d\n", nTime);
    printf("nBits:%x\n", nBits);
    printf("nNonce:%d\n", nNonce);
    

    /* uint8_t buf[20]; */
    /* size_t blen = 0; */
    
    /* blen = pack_varint(buf, 433223); */
    /* kyk_print_hex("varint ", buf, blen); */
    
    leveldb_close(db);
    
    return 0;
    
error:
    if(db) leveldb_close(db);
    return -1;
}

int blk_hashstr_to_bkey(const char *hstr, uint8_t *bkey, size_t klen)
{
    char prefix = 'b';
    int res = 0;
    
    *bkey = prefix;
    bkey++;
    
    res = hexstr_to_bytes(hstr, bkey, klen - 1);
    check(res > -1, "failed to convert hex to bytes");
    kyk_reverse(bkey, klen - 1);

    return 0;

error:
    return -1;
    
}

size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val)
{
    uint32_t n = 0;
    
    size_t i = 0;

    while(i < len) {
        unsigned char chData = *buf;
	buf++;
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80) {
	    i++;
            n++;
        } else {
	    *val = n;
	    i++;
            return i;
        }
    }

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


