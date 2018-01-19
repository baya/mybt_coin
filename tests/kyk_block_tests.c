#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "test_data.h"
#include "kyk_block.h"
#include "gens_block.h"
#include "kyk_message.h"
#include "mu_unit.h"

char *test_kyk_seri_blk()
{
    struct kyk_block* blk = NULL;
    uint8_t* buf = NULL;
    size_t blk_size = 0;
    size_t check_size = 0;
    int res = -1;

    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");

    res = kyk_get_blk_size(blk, &blk_size);
    check(res == 0, "Failed to test_kyk_seri_blk: kyk_get_blk_size failed");
    buf = calloc(blk_size, sizeof(*buf));
    check(res == 0, "Failed to test_kyk_seri_blk: buf calloc failed");

    res = kyk_seri_blk(buf, blk, &check_size);
    mu_assert(res == 0, "Failed to test_kyk_seri_blk");
    mu_assert(blk_size == check_size, "Failed to test_kyk_seri_blk");

    free(buf);
    kyk_free_block(blk);

    return NULL;

error:
    if(blk) kyk_free_block(blk);
    if(buf) free(buf);
    return "Failed to test_kyk_seri_blk";
}

char* test_kyk_seri_blkself()
{
    struct kyk_block* blk = NULL;
    uint8_t* buf = NULL;
    size_t blk_size = 0;
    size_t check_size = 0;
    int res = -1;

    blk = make_gens_block();
    check(blk, "Failed to test_kyk_seri_blkself: make_gens_block failed");
    
    res = kyk_get_blkself_size(blk, &blk_size);
    check(res == 0, "Failed to kyk_get_blk_selfsize: kyk_get_blkself_size failed");

    buf = calloc(blk_size, sizeof(*buf));
    check(buf, "Failed to test_kyk_seri_blkself: buf calloc failed");
    res = kyk_seri_blkself(buf, blk, &check_size);
    mu_assert(res == 0, "Failed to test_kyk_seri_blkself");
    mu_assert(blk_size == check_size, "Failed to test_kyk_seri_blkself");
    

    return NULL;

error:

    return "Failed kyk_seri_blkself";

}

char* test_deseri_blk_header()
{
    struct kyk_blk_header* hd = NULL;
    size_t len = 0;
    int res = -1;
    uint8_t target_mkl_root[] = {
	0x7d, 0xac, 0x2c, 0x56, 0x66, 0x81, 0x5c, 0x17,
	0xa3, 0xb3, 0x64, 0x27, 0xde, 0x37, 0xbb, 0x9d,
	0x2e, 0x2c, 0x5c, 0xce, 0xc3, 0xf8, 0x63, 0x3e,
	0xb9, 0x1a, 0x42, 0x05, 0xcb, 0x4c, 0x10, 0xff
    };
    uint8_t target_blk_hash[] = {
	0x00, 0x00, 0x00, 0x00, 0xd1, 0x14, 0x57, 0x90,
	0xa8, 0x69, 0x44, 0x03, 0xd4, 0x06, 0x3f, 0x32,
	0x3d, 0x49, 0x9e, 0x65, 0x5c, 0x83, 0x42, 0x68,
	0x34, 0xd4, 0xce, 0x2f, 0x8d, 0xd4, 0xa2, 0xee
    };
    uint8_t blk_hash[32];

    uint8_t buf[1000];
    
    memcpy(buf, BLK_HD, sizeof(BLK_HD));

    hd = calloc(1, sizeof(*hd));
    check(hd, "Failed to test_deseri_blk_header: calloc blk header failed");

    res = kyk_deseri_blk_header(hd, buf, &len);
    mu_assert(res == 0, "Failed to test_deseri_blk_header");
    mu_assert(len == sizeof(BLK_HD), "Failed to test_deseri_blk_header");
    mu_assert(kyk_digest_eq(hd -> mrk_root_hash, target_mkl_root, sizeof(target_mkl_root)), "Failed to test_deseri_blk_header");

    res = kyk_blk_hash256(blk_hash, hd);
    mu_assert(res == 0, "Failed to test_deseri_blk_header");
    mu_assert(kyk_digest_eq(blk_hash, target_blk_hash, sizeof(target_blk_hash)), "Failed to test_deseri_blk_header");

    return NULL;
    
error:

    return "test_deseri_blk_header failed";
}


char* test_deseri_new_block()
{
    struct kyk_block* blk = NULL;
    uint8_t target_blk_hash[] = {
	0x00, 0x00, 0x00, 0x00, 0xd1, 0x14, 0x57, 0x90,
	0xa8, 0x69, 0x44, 0x03, 0xd4, 0x06, 0x3f, 0x32,
	0x3d, 0x49, 0x9e, 0x65, 0x5c, 0x83, 0x42, 0x68,
	0x34, 0xd4, 0xce, 0x2f, 0x8d, 0xd4, 0xa2, 0xee
    };
    uint8_t blk_hash[32];

    uint8_t target_tx1_id[] = {
	0xb1, 0xfe, 0xa5, 0x24, 0x86, 0xce, 0x0c, 0x62,
	0xbb, 0x44, 0x2b, 0x53, 0x0a, 0x3f, 0x01, 0x32,
	0xb8, 0x26, 0xc7, 0x4e, 0x47, 0x3d, 0x1f, 0x2c,
	0x22, 0x0b, 0xfa, 0x78, 0x11, 0x1c, 0x50, 0x82
    };

    uint8_t target_tx2_id[] = {
	0xf4, 0x18, 0x4f, 0xc5, 0x96, 0x40, 0x3b, 0x9d,
	0x63, 0x87, 0x83, 0xcf, 0x57, 0xad, 0xfe, 0x4c,
	0x75, 0xc6, 0x05, 0xf6, 0x35, 0x6f, 0xbc, 0x91,
	0x33, 0x85, 0x30, 0xe9, 0x83, 0x1e, 0x9e, 0x16
    };

    uint8_t digest[32];
    struct kyk_tx* tx = NULL;
    int res = -1;
    size_t blk_size = 0;

    
    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_size);
    mu_assert(res == 0, "Failed to test_deseri_new_block");
    res = kyk_blk_hash256(blk_hash, blk -> hd);
    mu_assert(res == 0, "Failed to test_parse_block: kyk_blk_hash256 failed");
    mu_assert(kyk_digest_eq(blk_hash, target_blk_hash, sizeof(blk_hash)), "Failed to test_parse_block");

    tx = blk -> tx;
    res = kyk_tx_hash256(digest, tx);
    check(res == 0, "Failed to test_deseri_block: kyk_tx_hash256 failed");
    mu_assert(kyk_digest_eq(digest, target_tx1_id, sizeof(digest)), "Failed to test_deseri_block");

    tx = blk -> tx + 1;
    
    res = kyk_tx_hash256(digest, tx);
    check(res == 0, "Failed to test_deseri_block: kyk_tx_hash256 failed");
    mu_assert(kyk_digest_eq(digest, target_tx2_id, sizeof(digest)), "Failed to test_deseri_block");

    kyk_free_block(blk);
    
    return NULL;

error:

    return "Failed to test_deseri_block";
}

/*
 * The target block header is sourced from
 * https://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.json
 */
char* test_make_blk_header()
{
    struct kyk_block* blk = NULL;
    size_t blk_len = 0;
    struct kyk_blk_header* hd = NULL;
    struct kyk_tx* tx_list = NULL;
    uint32_t version = 1;
    uint8_t pre_blk_hash[32] = {
	0x00, 0x00, 0x00, 0x00, 0x2a, 0x22, 0xcf, 0xee,
	0x1f, 0x2c, 0x84, 0x6a, 0xdb, 0xd1, 0x2b, 0x3e,
	0x18, 0x3d, 0x4f, 0x97, 0x68, 0x3f, 0x85, 0xda,
	0xd0, 0x8a, 0x79, 0x78, 0x0a, 0x84, 0xbd, 0x55
    };
    uint32_t tts = 1231731025;
    uint32_t bts = 486604799;

    uint8_t blk_hash[32];
    uint8_t target_blk_hash[32] = {
	0x00, 0x00, 0x00, 0x00, 0xd1, 0x14, 0x57, 0x90,
	0xa8, 0x69, 0x44, 0x03, 0xd4, 0x06, 0x3f, 0x32,
	0x3d, 0x49, 0x9e, 0x65, 0x5c, 0x83, 0x42, 0x68,
	0x34, 0xd4, 0xce, 0x2f, 0x8d, 0xd4, 0xa2, 0xee
    };
    
    int res = -1;

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_len);
    check(res == 0, "Failed to test_make_blk_header: kyk_deseri_new_block failed");

    tx_list = blk -> tx;

    hd = kyk_make_blk_header(tx_list,
			     blk -> tx_count,
			     version,
			     pre_blk_hash,
			     tts,
			     bts);

    /* suppose we have got the nonce by mining */
    hd -> nonce = 1889418792;

    check(hd, "Failed to test_make_blk_header: kyk_make_blk_header failed");

    res = kyk_blk_hash256(blk_hash, hd);
    check(res == 0, "Failed to test_make_blk_header: kyk_blk_hash256 failed");

    mu_assert(kyk_digest_eq(blk_hash, target_blk_hash, sizeof(blk_hash)), "Failed to test_make_blk_header");
    
    return NULL;

error:

    return "Failed to test_make_blk_header";
}

char* test_kyk_make_block()
{
    struct kyk_block* blk = NULL;
    struct kyk_block* blk2 = NULL;
    size_t blk_len = 0;
    size_t target_blk_size = 490;
    int res = -1;

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_len);
    check(res == 0, "Failed to test_make_blk_header: kyk_deseri_new_block failed");

    res = kyk_make_block(&blk2, blk -> hd, blk -> tx, blk -> tx_count);
    mu_assert(res == 0, "Failed to test_kyk_make_block");
    mu_assert(blk2 -> blk_size == target_blk_size, "Failed to test_kyk_make_block: invalid blk_size");

    kyk_free_block(blk);
    free(blk2);
    
    return NULL;

error:
    if(blk) kyk_free_block(blk);
    if(blk2) free(blk2);
    return "Failed to test_kyk_make_block";
}

char* test_kyk_init_blk_hd_chain()
{
    struct kyk_blk_hd_chain* hdc = NULL;
    int res = -1;

    res = kyk_init_blk_hd_chain(&hdc);
    mu_assert(res == 0, "Failed to test_init_blk_hd_chain: kyk_init_blk_hd_chain failed");
    mu_assert(hdc, "Failed to test_kyk_init_blk_hd_chain: kyk_init_blk_hd_chain failed");
    mu_assert(hdc -> len == 0, "Failed to test_kyk_init_blk_hd_chain: kyk_init_blk_hd_chain failed");
    mu_assert(hdc -> hd_list == NULL, "Failed to test_kyk_init_blk_hd_chain: kyk_init_blk_hd_chain failed");
    
    kyk_free_blk_hd_chain(hdc);

    return NULL;
}

char* test_kyk_seri_blk_hd_chain()
{
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_bon_buff* bbuf = NULL;
    uint8_t target_buf[160] = {
	0x01, 0x00, 0x00, 0x00, 0x55, 0xbd, 0x84, 0x0a,
	0x78, 0x79, 0x8a, 0xd0, 0xda, 0x85, 0x3f, 0x68,
	0x97, 0x4f, 0x3d, 0x18, 0x3e, 0x2b, 0xd1, 0xdb,
	0x6a, 0x84, 0x2c, 0x1f, 0xee, 0xcf, 0x22, 0x2a,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x10, 0x4c, 0xcb,
	0x05, 0x42, 0x1a, 0xb9, 0x3e, 0x63, 0xf8, 0xc3,
	0xce, 0x5c, 0x2c, 0x2e, 0x9d, 0xbb, 0x37, 0xde,
	0x27, 0x64, 0xb3, 0xa3, 0x17, 0x5c, 0x81, 0x66,
	0x56, 0x2c, 0xac, 0x7d, 0x51, 0xb9, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x28, 0x3e, 0x9e, 0x70,
	0x01, 0x00, 0x00, 0x00, 0xee, 0xa2, 0xd4, 0x8d,
	0x2f, 0xce, 0xd4, 0x34, 0x68, 0x42, 0x83, 0x5c,
	0x65, 0x9e, 0x49, 0x3d, 0x32, 0x3f, 0x06, 0xd4,
	0x03, 0x44, 0x69, 0xa8, 0x90, 0x57, 0x14, 0xd1,
	0x00, 0x00, 0x00, 0x00, 0xf2, 0x93, 0xc8, 0x69,
	0x73, 0xe7, 0x58, 0xcc, 0xd1, 0x19, 0x75, 0xfa,
	0x46, 0x4d, 0x4c, 0x3e, 0x85, 0x00, 0x97, 0x9c,
	0x95, 0x42, 0x5c, 0x7b, 0xe6, 0xf0, 0xa6, 0x53,
	0x14, 0xd2, 0xf2, 0xd5, 0xc9, 0xba, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x07, 0xa8, 0xf2, 0x26,
    };
    int res = -1;

    res = make_testing_blk_hd_chain(&hdc);
    check(res == 0, "Failed to test_kyk_seri_blk_hd_chain");
    
    res = kyk_seri_blk_hd_chain(&bbuf, hdc);
    check(res == 0, "Failed to test_kyk_seri_blk_hd_chain");
    mu_assert(kyk_digest_eq(bbuf -> base, target_buf, bbuf -> len), "Failed to test_kyk_seri_blk_hd_chain");
    
    return NULL;

error:

    return "Failed to test_kyk_seri_blk_hd_chain";

}

char* test_kyk_deseri_blk_hd_chain()
{
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_blk_header* hd = NULL;
    uint8_t buf[160] = {
	0x01, 0x00, 0x00, 0x00, 0x55, 0xbd, 0x84, 0x0a,
	0x78, 0x79, 0x8a, 0xd0, 0xda, 0x85, 0x3f, 0x68,
	0x97, 0x4f, 0x3d, 0x18, 0x3e, 0x2b, 0xd1, 0xdb,
	0x6a, 0x84, 0x2c, 0x1f, 0xee, 0xcf, 0x22, 0x2a,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x10, 0x4c, 0xcb,
	0x05, 0x42, 0x1a, 0xb9, 0x3e, 0x63, 0xf8, 0xc3,
	0xce, 0x5c, 0x2c, 0x2e, 0x9d, 0xbb, 0x37, 0xde,
	0x27, 0x64, 0xb3, 0xa3, 0x17, 0x5c, 0x81, 0x66,
	0x56, 0x2c, 0xac, 0x7d, 0x51, 0xb9, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x28, 0x3e, 0x9e, 0x70,
	0x01, 0x00, 0x00, 0x00, 0xee, 0xa2, 0xd4, 0x8d,
	0x2f, 0xce, 0xd4, 0x34, 0x68, 0x42, 0x83, 0x5c,
	0x65, 0x9e, 0x49, 0x3d, 0x32, 0x3f, 0x06, 0xd4,
	0x03, 0x44, 0x69, 0xa8, 0x90, 0x57, 0x14, 0xd1,
	0x00, 0x00, 0x00, 0x00, 0xf2, 0x93, 0xc8, 0x69,
	0x73, 0xe7, 0x58, 0xcc, 0xd1, 0x19, 0x75, 0xfa,
	0x46, 0x4d, 0x4c, 0x3e, 0x85, 0x00, 0x97, 0x9c,
	0x95, 0x42, 0x5c, 0x7b, 0xe6, 0xf0, 0xa6, 0x53,
	0x14, 0xd2, 0xf2, 0xd5, 0xc9, 0xba, 0x6a, 0x49,
	0xff, 0xff, 0x00, 0x1d, 0x07, 0xa8, 0xf2, 0x26,
    };
    uint8_t digest[32];
    size_t hd_count = 2;
    int res = -1;    

    res = kyk_deseri_blk_hd_chain(&hdc, buf, sizeof(buf));
    mu_assert(res == 0, "Failed to test_kyk_deseri_blk_hd_chain");
    mu_assert(hdc -> len == hd_count, "Failed to test_kyk_deseri_blk_hd_chain");

    hd = hdc -> hd_list;

    kyk_blk_hash256(digest, hd);
    mu_assert(kyk_digest_eq(digest, BLK_HASH, sizeof(digest)), "Failed to test_kyk_deseri_blk_hd_chain");

    hd++;
    kyk_blk_hash256(digest, hd);
    mu_assert(kyk_digest_eq(digest, BLK2_HASH, sizeof(digest)), "Failed to test_kyk_deseri_blk_hd_chain");
    
    return NULL;
}

char* test_kyk_get_blk_size()
{
    struct kyk_block* blk = NULL;
    size_t blk_size1 = 0;
    size_t blk_size2 = 0;
    int res = -1;

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_size1);
    check(res == 0, "Failed to test_kyk_get_blk_size: kyk_deseri_new_block failed");

    res = kyk_get_blk_size(blk, &blk_size2);
    mu_assert(res == 0, "Failed to test_kyk_get_blk_size");
    mu_assert(blk_size2 == blk_size1, "Failed to test_kyk_get_blk_size");

    kyk_free_block(blk);
    return NULL;

error:

    return "Failed to test_kyk_get_blk_size";
}


char* test_kyk_get_blkself_size()
{
    struct kyk_block* blk = NULL;
    size_t blk_size1 = 0;
    size_t blk_size2 = 0;
    int res = -1;

    res = kyk_deseri_new_block(&blk, BLOCK_BUF, &blk_size1);
    check(res == 0, "Failed to test_kyk_get_blkself_size: kyk_deseri_new_block failed");

    res = kyk_get_blkself_size(blk, &blk_size2);
    mu_assert(res == 0, "Failed to test_kyk_get_blkself_size");
    mu_assert(blk_size2 == blk_size1 + 8, "Failed to test_kyk_get_blkself_size");

    kyk_free_block(blk);
    return NULL;

error:

    return "Failed to test_kyk_get_blk_selfsize";
}

char* test_kyk_tail_hd_chain()
{
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_blk_header* hd = NULL;
    uint8_t target_mkl_root[32] = {
	0xd5, 0xf2, 0xd2, 0x14, 0x53, 0xa6, 0xf0, 0xe6,
	0x7b, 0x5c, 0x42, 0x95, 0x9c, 0x97, 0x00, 0x85,
	0x3e, 0x4c, 0x4d, 0x46, 0xfa, 0x75, 0x19, 0xd1,
	0xcc, 0x58, 0xe7, 0x73, 0x69, 0xc8, 0x93, 0xf2
    };
    int res = -1;    

    res = kyk_deseri_blk_hd_chain(&hdc, BLK_HD2_CHAIN_BUF, sizeof(BLK_HD2_CHAIN_BUF));
    check(res == 0, "Failed to test_kyk_tail_hd_chain: kyk_deseri_blk_hd_chain failed");

    res = kyk_tail_hd_chain(&hd, hdc);
    mu_assert(res == 0, "Failed to test_kyk_tail_hd_chain");
    mu_assert(hd, "Failed to test_kyk_tail_hd_chain");
    mu_assert(kyk_digest_eq(hd -> mrk_root_hash, target_mkl_root, sizeof(target_mkl_root)), "Failed to test_kyk_tail_hd_chain");


    return NULL;
    
error:

    return "Failed to test_kyk_tail_hd_chain";

}

char* test_kyk_make_coinbase_block()
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_block* blk = NULL;
    const uint8_t pubkey[33] = {
	0x02, 0x76, 0xe9, 0xd1, 0x87, 0x81, 0xd2, 0xb3,
	0xad, 0x7e, 0x5a, 0xc8, 0xd3, 0x8e, 0xf0, 0x89,
	0x9f, 0x94, 0x42, 0xf8, 0x09, 0xbb, 0xbc, 0x67,
	0xe5, 0x27, 0x27, 0x8d, 0xa2, 0xae, 0xdc, 0x93,
	0xa4
    };
    uint8_t target_prev_blk_hash[32] = {
	0x00, 0x00, 0x00, 0x00, 0x6a, 0x62, 0x5f, 0x06,
	0x63, 0x6b, 0x8b, 0xb6, 0xac, 0x7b, 0x96, 0x0a,
	0x8d, 0x03, 0x70, 0x5d, 0x1a, 0xce, 0x08, 0xb1,
	0xa1, 0x9d, 0xa3, 0xfd, 0xcc, 0x99, 0xdd, 0xbd
    };
    const char* note = "voidcoin";
    int res = -1;

    uint8_t buf[1000];
    size_t check_size;

    res = kyk_deseri_blk_hd_chain(&hd_chain, BTC_012_BLK_HD_BUF, sizeof(BTC_012_BLK_HD_BUF));
    check(res == 0, "Failed to test_kyk_make_coinbase_block: kyk_deseri_blk_hd_chain failed");

    res = kyk_make_coinbase_block(&blk, hd_chain, note, pubkey, sizeof(pubkey));
    mu_assert(res == 0, "Failed to test_kyk_make_coinbase_block");
    mu_assert(kyk_digest_eq(blk -> hd -> pre_blk_hash, target_prev_blk_hash, 32), "Failed to test_kyk_make_coinbase_block");

    if(0){
	kyk_seri_blk(buf, blk, &check_size);
	FILE* fp = fopen("/tmp/test_kyk_make_coinbase_block_result.bin", "wb");
	fwrite(buf, sizeof(*buf), check_size, fp);
    }

    return NULL;

error:

    return "Failed to test_kyk_make_coinbase_block";

}

char* test_kyk_deseri_block_from_blk_message()
{
    struct kyk_block* blk;
    ptl_message* ptl_msg = NULL;
    uint8_t msg_buf[] = {
	0xf9, 0xbe, 0xb4, 0xd9, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb7, 0x00, 0x00, 0x00, 0x8c, 0x0e, 0x5c, 0x05, 0x01, 0x00, 0x00, 0x00, 0xf3, 0xf8, 0x8b, 0x54,
	0x7f, 0x96, 0xdf, 0x8a, 0x9f, 0x79, 0x81, 0x16, 0xe2, 0x5a, 0xf9, 0x96, 0x72, 0xea, 0xbd, 0xc1,
	0x2e, 0x01, 0xa3, 0xb2, 0xf8, 0xc1, 0xf8, 0x9e, 0x6c, 0x87, 0x00, 0x00, 0x16, 0x4e, 0x1e, 0x42,
	0xcc, 0x49, 0x10, 0xaf, 0x03, 0xb1, 0x12, 0x63, 0xe8, 0x7c, 0xe6, 0xca, 0xa2, 0xe4, 0xa9, 0xfb,
	0xd5, 0x30, 0xd7, 0x34, 0xe0, 0x63, 0xa7, 0x0f, 0x3e, 0xba, 0x99, 0xff, 0x7f, 0x19, 0x53, 0x5a,
	0xff, 0xff, 0x00, 0x1f, 0x1b, 0x9c, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xff, 0xff, 0x11, 0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x09, 0x76, 0x6f, 0x69, 0x64, 0x20,
	0x63, 0x6f, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0xe4, 0x0b, 0x54, 0x02, 0x00, 0x00,
	0x00, 0x19, 0x76, 0xa9, 0x14, 0x1d, 0xb9, 0x27, 0x79, 0x7e, 0x93, 0x14, 0x72, 0x1d, 0x19, 0x3a,
	0x18, 0x41, 0x71, 0xf3, 0xa3, 0x7c, 0xe3, 0x4c, 0x68, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00
    };

    int res = -1;
    blk = calloc(1, sizeof(*blk));

    res = kyk_deseri_new_ptl_message(&ptl_msg, msg_buf, sizeof(msg_buf));
    check(res == 0, "Failed to test_kyk_deseri_block_from_blk_message: kyk_deseri_new_ptl_message failed");

    res = kyk_deseri_block_from_blk_message(blk, ptl_msg, NULL);
    mu_assert(res == 0, "Failed to test_kyk_deseri_block_from_blk_message");

    /* kyk_print_block(blk); */
    
    return NULL;

error:

    return "Failed to test_kyk_deseri_block_from_blk_message";
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_seri_blk);
    mu_run_test(test_kyk_seri_blkself);
    mu_run_test(test_deseri_blk_header);
    mu_run_test(test_deseri_new_block);
    mu_run_test(test_make_blk_header);
    mu_run_test(test_kyk_make_block);
    mu_run_test(test_kyk_init_blk_hd_chain);
    mu_run_test(test_kyk_seri_blk_hd_chain);
    mu_run_test(test_kyk_get_blk_size);
    mu_run_test(test_kyk_get_blkself_size);
    mu_run_test(test_kyk_tail_hd_chain);
    mu_run_test(test_kyk_make_coinbase_block);
    mu_run_test(test_kyk_deseri_block_from_blk_message);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
