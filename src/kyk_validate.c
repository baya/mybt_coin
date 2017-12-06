#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include "kyk_validate.h"
#include "kyk_utils.h"
#include "kyk_block.h"
#include "kyk_tx.h"
#include "dbg.h"


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

    return 0;

error:

    return -1;
}

