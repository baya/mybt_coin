#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "kyk_block.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "mu_unit.h"

int main()
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

    kyk_print_hex("block hash", dgst, sizeof(dgst));
    
}
