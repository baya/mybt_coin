#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#include "kyk_validate.h"
#include "kyk_utils.h"
#include "kyk_block.h"
#include "kyk_tx.h"
#include "kyk_difficulty.h"
#include "dbg.h"

static int validate_hd_bts(const struct kyk_blk_header* hd);

int kyk_validate_blk_header(struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* outHd)
{
    check(hd_chain, "Failed to validate_blk_header: hd_chain is NULL");
    check(outHd, "Failed to validate_blk_header: hd is NULL");
    check(outHd -> pre_blk_hash, "Failed to validate_blk_header: pre_blk_hash is NULL");
    struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_blk_header* prev_hd = NULL;
    uint8_t digest[32];
    int res = -1;

    hdc = hd_chain;

    if(hdc -> len == 0){
	return 0;
    }

    prev_hd = hdc -> hd_list + hd_chain -> len - 1;
    check(prev_hd, "Failed to kyk_validate_blk_header: prev_hd is NULL");
    
    res = kyk_blk_hash256(digest, prev_hd);
    check(res == 0, "Failed to kyk_validate_blk_header: kyk_blk_hash256 failed");
    check(kyk_digest_eq(outHd -> pre_blk_hash, digest, sizeof(digest)), "Failed to kyk_validate_blk_header: invalid pre_blk_hash");

    res = validate_hd_bts(outHd);
    check(res == 0, "Failed to kyk_validate_blk_header: validate_hd_bts failed");

    return 0;

error:

    return -1;
}

int validate_hd_bts(const struct kyk_blk_header* hd)
{
    mpz_t tg, hs;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int res = -1;

    mpz_init(tg);
    mpz_set_ui(tg, 0);

    mpz_init(hs);
    mpz_set_ui(hs, 0);

    /* bts to target */
    kyk_bts2target(hd -> bts, tg);

    res = kyk_blk_hash256(digest, hd);
    check(res == 0, "Failed to validate_hd_bts: kyk_blk_hash256 failed");

    mpz_import(hs, sizeof(digest), 1, 1, 1, 0, digest);
    check(mpz_cmp(hs, tg) <= 0, "Failed to validate_hd_bts: block hash dosen't reach target");

    return 0;
    
error:

    return -1;

}

