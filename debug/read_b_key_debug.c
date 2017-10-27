#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "kyk_utils.h"
#include "dbg.h"

int blk_hashstr_to_bkey(const char *hstr, uint8_t *bkey, size_t klen);
size_t pack_varint(uint8_t *buf, int n);
size_t read_varint(const uint8_t *buf, size_t len, uint32_t *val);

int main()
{
    leveldb_t *db = NULL;
    leveldb_options_t *db_opts = NULL;
    char *errptr = NULL;
    char *db_path = "/tmp/bitcoin-block-data/blocks/index";
    leveldb_readoptions_t *read_opts = NULL;
    uint8_t bkey[33];
    char *value = NULL;
    char *valptr = NULL;
    size_t vlen = 0;
    //char *blk_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    char *blk_hash = "0000000099c744455f58e6c6e98b671e1bf7f37346bfd4cf5d0274ad8ee660cb";
    int res = 0;
    errno = 0;
    int nVersion = 0;
    int nHeight = 0;
    uint32_t nStatus = 0;
    unsigned int nTx = 0;

    res = blk_hashstr_to_bkey(blk_hash, bkey, sizeof(bkey));
    check(res > -1, "failed to convert block hash to bkey");
    kyk_print_hex("bkey ", bkey, sizeof(bkey));

    db_opts = leveldb_options_create();
    db = leveldb_open(db_opts, db_path, &errptr);
    check(errptr == NULL, "open db error: %s", errptr);

    read_opts = leveldb_readoptions_create();

    value = leveldb_get(db, read_opts, (char *)bkey, sizeof(bkey), &vlen, &errptr);
    check(errptr == NULL, "get value error: %s", errptr);
    kyk_print_hex("value ", (unsigned char*)value, vlen);

    valptr = value;
    size_t ofst = 0;
    ofst = read_varint(valptr, vlen - (valptr - value), &nVersion);
    valptr += ofst;
    ofst = read_varint(valptr, vlen - (valptr - value), &nHeight);
    printf("??????%zu\n", ofst);
    valptr += ofst;
    ofst = read_varint(valptr, vlen - (valptr - value), &nStatus);
    printf("??????%zu\n", ofst);
    printf("nVersion: %llu\n", nVersion);
    printf("nHeight: %llu\n", nHeight);
    printf("nStatus: %d\n", (uint32_t)nStatus);

    uint8_t buf[10];
    size_t blen = 0;
    blen = pack_varint(buf, 29);
    kyk_print_hex("gg", buf, blen);


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


