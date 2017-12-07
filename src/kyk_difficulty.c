#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kyk_difficulty.h"


uint64_t kyk_bts2dlt(uint32_t bts)
{

    uint64_t res;
    mpz_t tg, dlt1_tg, q;
    
    mpz_init(tg);
    mpz_init(dlt1_tg);
    mpz_init(q);
    
    mpz_set_ui(tg, 0);
    mpz_set_str(dlt1_tg, DLT1_TARGET_HEX_STR, 0);
    kyk_bts2target(bts, tg);

    mpz_cdiv_q(q, dlt1_tg, tg);

    res = mpz_get_ui(q);

    mpz_clear(tg);
    mpz_clear(dlt1_tg);
    mpz_clear(q);

    return res;

}

/* When a variable of type mpz_t is used as a function parameter, it's effectively a call-by-reference, meaning anything the function does to it will be be done to the original in the caller */
void kyk_bts2target(uint32_t bts, mpz_t tg)
{
    uint8_t ep = bts >> 24;
    uint32_t mt = bts & 0xffffff;

    mpz_ui_pow_ui(tg, 2, 8 * (ep - 3));
    mpz_mul_ui(tg, tg, mt);
}

/* difficulty = difficulty_1_target / current_target         */
/* so then current_target = difficulty_1_target / difficulty */
int kyk_dlt2target(uint32_t dlt, mpz_t tg)
{
    mpz_t q, dlt1_tg;

    mpz_init(q);
    mpz_set_ui(q, dlt);
    
    mpz_init(dlt1_tg);
    mpz_set_str(dlt1_tg, DLT1_TARGET_HEX_STR, 0);

    mpz_cdiv_q(tg, dlt1_tg, q);

    mpz_clear(q);
    mpz_clear(dlt1_tg);
 
    return 0;
}

int kyk_target2bts(mpz_t tg, uint32_t* bts)
{
}

int kyk_dlt2bts(uint32_t dlt, uint32_t* bts)
{
    return 0;
}

