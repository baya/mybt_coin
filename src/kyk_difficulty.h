#ifndef KYK_DIFFICULTY_H__
#define KYK_DIFFICULTY_H__

#include <gmp.h>

#define DLT1_TARGET_HEX_STR "0x00000000FFFF0000000000000000000000000000000000000000000000000000"

void kyk_bts2target(uint32_t bts, mpz_t tg);
int kyk_target2bts(mpz_t tg, uint32_t* new_bts);

uint64_t kyk_bts2dlt(uint32_t bts);
int kyk_dlt2target(uint32_t dlt, mpz_t tg);
    
#endif
