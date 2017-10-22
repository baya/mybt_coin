#ifndef KYK_DIFFICULTY_H__
#define KYK_DIFFICULTY_H__

#include <gmp.h>

uint32_t kyk_bts2dlt(uint32_t bts);
void kyk_bts2target(uint32_t bts, mpz_t tg);
    
#endif
