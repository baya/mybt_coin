#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kyk_sha.h"

unsigned char * kyk_sha256(const char *str, size_t len)
{
    unsigned char *dgst;
    SHA256_CTX ctx;

    dgst = (unsigned char*)malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)str, len);
    SHA256_Final(dgst, &ctx);

    return dgst;
}


unsigned char * kyk_dble_sha256(const char *str, size_t len)
{
    unsigned char *dg1;
    unsigned char *dg2;
    
    dg1 = kyk_sha256(str, len);
    dg2 = kyk_sha256((char *)dg1, SHA256_DIGEST_LENGTH);
    
    free(dg1);

    return dg2;
}

void kyk_dgst_rmd160(uint8_t *digest, const uint8_t *message, size_t len)
{
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, message, len);
    RIPEMD160_Final(digest, &ctx);
}

/* inverted hash*/
struct kyk_digst *kyk_inver_hash(const char *src, size_t len)
{
    unsigned char *dg;
    struct kyk_digst *ivhash;
    size_t dg_len = SHA256_DIGEST_LENGTH;

    dg = kyk_dble_sha256(src, len);
    ivhash = (struct kyk_digst*) malloc(sizeof(struct kyk_digst));
    ivhash -> len = dg_len;
    ivhash -> body = (unsigned char*)malloc(dg_len * sizeof(unsigned char));
    
    if(ivhash -> body == NULL){
	fprintf(stderr, "failed in malloc kyk inver hash\n");
	exit(1);
    }

    for(int i=dg_len -1; i >= 0; i--){
	ivhash->body[dg_len - 1 - i] = dg[i];
    }


    free(dg);

    return ivhash;
}

void kyk_dgst_sha256(uint8_t *digest, const uint8_t *message, size_t len)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
}

void kyk_dgst_hash256(uint8_t *digest, const uint8_t *message, size_t len)
{
    uint8_t tmp[SHA256_DIGEST_LENGTH];
    kyk_dgst_sha256(tmp, message, len);
    kyk_dgst_sha256(digest, tmp, SHA256_DIGEST_LENGTH);
}

void kyk_dgst_hash160(uint8_t *digest, const uint8_t *message, size_t len)
{
    uint8_t tmp[SHA256_DIGEST_LENGTH];
    kyk_dgst_sha256(tmp, message, len);
    kyk_dgst_rmd160(digest, tmp, SHA256_DIGEST_LENGTH);
}

void kyk_free_digst(struct kyk_digst *dg)
{
    if(dg != NULL){
	if(dg -> body != NULL){
	    free(dg -> body);
	}
	free(dg);
    }
}






