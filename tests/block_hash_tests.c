#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "kyk_block.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "mu_unit.h"

char *test_block_hash()
{
    struct kyk_blk_header blk_hd;
    uint8_t hd_buf[1000];
    size_t hd_len;
    uint8_t dgst[SHA256_DIGEST_LENGTH];
    

    blk_hd.version = 1;
    kyk_parse_hex(blk_hd.pre_blk_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    kyk_parse_hex(blk_hd.mrk_root_hash, "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    blk_hd.tts = 1231006505;
    blk_hd.bts = 486604799;
    blk_hd.nonce = 2083236893;

    hd_len = kyk_seri_blk_hd(hd_buf, &blk_hd);

    kyk_dgst_hash256(dgst, hd_buf, hd_len);
    kyk_reverse(dgst, sizeof(dgst));

    uint8_t target_hsh[SHA256_DIGEST_LENGTH];
    kyk_parse_hex(target_hsh, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    int res = kyk_digest_eq(dgst, target_hsh, SHA256_DIGEST_LENGTH);

    mu_assert(res, "failed to get the correct block hash");

    return NULL;
}


char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_block_hash);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

