#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "kyk_block.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "kyk_difficulty.h"
#include "beej_pack.h"


int main()
{
    struct kyk_blk_header blk_hd;
    uint8_t hd_buf[1000];
    size_t len;
    uint8_t dgst[SHA256_DIGEST_LENGTH];

    blk_hd.version = 1;
    kyk_parse_hex(blk_hd.pre_blk_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    kyk_parse_hex(blk_hd.mrk_root_hash, "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    blk_hd.tts = 1231006505;
    blk_hd.bts = 486604799;
    
    /*
     * 在已经知道目标 nonce 的情况下, 如果从 0 开始跑计算，需要跑 20 多亿次(准确地说是 40 多亿次) sha256 计算，在没有矿机的情况下，这个实验就没有办法在较短的时间内做下去了
     * 所以将 nonce 设置为一个较大的数，这样只要跑 1 千万次(准确地说是 2 千万次, 因为比特币系统中算一次 hash 要跑两次 sha256 计算) sha256 计算就能得到结果.
    */
    
    blk_hd.nonce = 2082236893;

    uint32_t dlt;
    mpz_t tg, hs;
    mpz_init(tg);
    mpz_set_ui(tg, 0);

    mpz_init(hs);
    mpz_set_ui(hs, 0);

    /* bts to difficulty */
    dlt = kyk_bts2dlt(blk_hd.bts);

    /* bts to target */
    kyk_bts2target(blk_hd.bts, tg);
    gmp_printf("0x%02x => target is: 0x%Zx\n", blk_hd.bts, tg);
    gmp_printf("0x%02x => difficulty is: %u\n", blk_hd.bts, dlt);

    len = kyk_seri_blk_hd_without_nonce(hd_buf, &blk_hd);
    
    do{	
    	beej_pack(hd_buf+len, "<L", blk_hd.nonce);
    	kyk_dgst_hash256(dgst, hd_buf, KYK_BLK_HD_LEN);
    	kyk_reverse(dgst, SHA256_DIGEST_LENGTH);
	mpz_import(hs, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, dgst);
	if(mpz_cmp(hs, tg) > 0){
	    blk_hd.nonce += 1;
	} else {
	    break;
	}
    } while(1);

    kyk_print_hex("got block hash", dgst, sizeof(dgst));

    printf("got nonce: %u\n", blk_hd.nonce);
}
