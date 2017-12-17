#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "kyk_defs.h"
#include "dbg.h"
#include "beej_pack.h"

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


void build_fkey(uint8_t *fkey, uint32_t n);
size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);
size_t read_varint64(const uint8_t *buf, size_t len, uint64_t *val);

int main(int argc, char *argv[])
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = "/tmp/bitcoin-block-data/blocks/index";
    leveldb_readoptions_t *read_opts = NULL;
    uint8_t fkey[5];
    uint32_t n = 0;
    char *value = NULL;
    char *valptr = NULL;
    size_t vlen = 0;

    unsigned int nBlocks;      //!< number of blocks stored in file
    unsigned int nSize;        //!< number of used bytes of block file
    unsigned int nUndoSize;    //!< number of used bytes in the undo file
    unsigned int nHeightFirst; //!< lowest height of block in file
    unsigned int nHeightLast;  //!< highest height of block in file
    uint64_t nTimeFirst;       //!< earliest time of block in file
    uint64_t nTimeLast;        //!< latest time of block in file

    if(argc != 2){
	printf("pelase provide a file number, such as 0\n");
	return 1;
    }

    n = (uint32_t)strtol(argv[1], NULL, 10);
    build_fkey(fkey, n);

    kyk_print_hex("fkey ", fkey, sizeof(fkey));

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)fkey, sizeof(fkey), &vlen, &errptr);
    check(errptr == NULL, "get value error: %s", errptr);
    kyk_print_hex("raw value ", (unsigned char*)value, vlen);

    valptr = value;
    size_t ofst = 0;
    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nBlocks);
    valptr += ofst;

    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nSize);
    valptr += ofst;

    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nUndoSize);
    valptr += ofst;

    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nHeightFirst);
    valptr += ofst;

    ofst = read_varint((uint8_t *)valptr, vlen - (valptr - value), (uint32_t *)&nHeightLast);
    valptr += ofst;

    ofst = read_varint64((uint8_t *)valptr, vlen - (valptr - value), &nTimeFirst);
    valptr += ofst;

    ofst = read_varint64((uint8_t *)valptr, vlen - (valptr - value), &nTimeLast);
    
    printf("nBlocks: %d (number of blocks stored in file)\n", nBlocks);
    printf("nSize: %d (number of used bytes of block file)\n", nSize);
    printf("nUndoSize: %d (number of used bytes in the undo file)\n", nUndoSize);
    printf("nHeightFirst: %d (lowest height of block in file)\n", nHeightFirst);
    printf("nHeightLast: %d (highest height of block in file)\n", nHeightLast);
    printf("nTimeFirst: %llu (earliest time of block in file)\n", nTimeFirst);
    printf("nTimeLast: %llu (latest time of block in file)\n", nTimeLast);
    

    leveldb_close(db);

    return 0;

error:
    if(db) leveldb_close(db);
    return -1;
    

}


void build_fkey(uint8_t *fkey, uint32_t n)
{
    char prefix = 'f';

    *fkey = prefix;
    fkey++;
    beej_pack(fkey, "<L", n);
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
