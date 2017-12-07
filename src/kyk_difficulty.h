#ifndef KYK_DIFFICULTY_H__
#define KYK_DIFFICULTY_H__

#include <gmp.h>

#define DLT1_TARGET_HEX_STR "0x00000000FFFF0000000000000000000000000000000000000000000000000000"

uint64_t kyk_bts2dlt(uint32_t bts);
void kyk_bts2target(uint32_t bts, mpz_t tg);
int kyk_dlt2target(uint32_t dlt, mpz_t tg);
    
#endif
