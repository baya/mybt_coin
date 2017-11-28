#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "kyk_block.h"
#include "kyk_buff.h"
#include "gens_block.h"
#include "mu_unit.h"

/*
 * This block header is sourced from https://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.hex
*/
static uint8_t BLK_HD[KYK_BLK_HD_LEN] = {
    0x01, 0x00, 0x00, 0x00, 0x55, 0xbd, 0x84, 0x0a,
    0x78, 0x79, 0x8a, 0xd0, 0xda, 0x85, 0x3f, 0x68,
    0x97, 0x4f, 0x3d, 0x18, 0x3e, 0x2b, 0xd1, 0xdb,
    0x6a, 0x84, 0x2c, 0x1f, 0xee, 0xcf, 0x22, 0x2a,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x10, 0x4c, 0xcb,
    0x05, 0x42, 0x1a, 0xb9, 0x3e, 0x63, 0xf8, 0xc3,
    0xce, 0x5c, 0x2c, 0x2e, 0x9d, 0xbb, 0x37, 0xde,
    0x27, 0x64, 0xb3, 0xa3, 0x17, 0x5c, 0x81, 0x66,
    0x56, 0x2c, 0xac, 0x7d, 0x51, 0xb9, 0x6a, 0x49,
    0xff, 0xff, 0x00, 0x1d, 0x28, 0x3e, 0x9e, 0x70
};

char *test_kyk_ser_blk()
{
    struct kyk_block* blk = NULL;
    struct kyk_buff* buf = NULL;
    char *errmsg = "failed to test kyk ser block";

    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");

    buf = create_kyk_buff(1000);
    check(buf != NULL, "failed to create kyk buff");

    kyk_ser_blk(buf, blk);

    mu_assert(buf -> idx == blk -> blk_size, "failed to get the correct block len");

    return NULL;

error:
    if(buf) free_kyk_buff(buf);
    if(blk) kyk_free_block(blk);
    return errmsg;
    
}

char* test_make_blk_header()
{
    return NULL;
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

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_ser_blk);
    mu_run_test(test_make_blk_header);
    mu_run_test(test_deseri_blk_header);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
