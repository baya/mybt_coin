#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kyk_difficulty.h"


#define DLT1_TARGET_HEX_STR "0x00000000FFFF0000000000000000000000000000000000000000000000000000"

uint32_t kyk_bts2dlt(uint32_t bts)
{

    uint32_t res;
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

void kyk_bts2target(uint32_t bts, mpz_t tg)
{
    uint8_t ep = bts >> 24;
    uint32_t mt = bts & 0xffffff;

    mpz_ui_pow_ui(tg, 2, 8 * (ep - 3));
    mpz_mul_ui(tg, tg, mt);
}
