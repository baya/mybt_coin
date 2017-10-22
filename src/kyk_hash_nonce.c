#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "kyk_block.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "kyk_difficulty.h"
#include "beej_pack.h"

void kyk_hsh_nonce(struct kyk_blk_header *hd)
{
    mpz_t tg, hs;
    size_t len;
    uint8_t hd_buf[KYK_BLK_HD_LEN + 20];
    uint8_t dgst[SHA256_DIGEST_LENGTH];
    
    mpz_init(tg);
    mpz_set_ui(tg, 0);

    mpz_init(hs);
    mpz_set_ui(hs, 0);

    /* bts to target */
    kyk_bts2target(hd -> bts, tg);    

    len = kyk_seri_blk_hd_without_nonce(hd_buf, hd);

    do{
	printf("running...%u\n", hd -> nonce);
    	beej_pack(hd_buf+len, "<L", hd -> nonce);
    	kyk_dgst_hash256(dgst, hd_buf, KYK_BLK_HD_LEN);
    	kyk_reverse(dgst, SHA256_DIGEST_LENGTH);
	mpz_import(hs, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, dgst);
	if(mpz_cmp(hs, tg) > 0){
	    hd -> nonce += 1;
	} else {
	    break;
	}
	
    } while(1);

    kyk_print_hex("got block hash", dgst, sizeof(dgst));

    printf("got nonce: %u\n", hd -> nonce);
    gmp_printf("0x%02x => target is: 0x%Zx\n", hd -> bts, tg);

}
