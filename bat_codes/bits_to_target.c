#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>


#define DLT1_TARGET_HEX_STR "0x00000000FFFF0000000000000000000000000000000000000000000000000000"

void bts2target(uint32_t bts, mpz_t tg);
uint32_t bts2dlt(uint32_t bts);

/*
 * 0x1b0404cb
 * 0x0404cb * 2**(8*(0x1b - 3)) = 0x00000000000404CB000000000000000000000000000000000000000000000000
 */
int main()
{

    //uint32_t bts = 0x1b0404cb;
    uint32_t bts = 0x1d00ffff;
    uint32_t dlt;
    mpz_t tg;
    mpz_init(tg);
    mpz_set_ui(tg, 0);

    bts2target(bts, tg);
    dlt = bts2dlt(bts);
    gmp_printf("0x%02x => target is: 0x%Zx\n", bts, tg);
    gmp_printf("0x%02x => difficulty is: %u\n", bts, dlt);
}

uint32_t bts2dlt(uint32_t bts)
{

    uint32_t res;
    mpz_t tg, dlt1_tg, q;
    
    mpz_init(tg);
    mpz_init(dlt1_tg);
    mpz_init(q);
    
    mpz_set_ui(tg, 0);
    mpz_set_str(dlt1_tg, DLT1_TARGET_HEX_STR, 0);
    bts2target(bts, tg);

    mpz_cdiv_q(q, dlt1_tg, tg);

    res = mpz_get_ui(q);

    mpz_clear(tg);
    mpz_clear(dlt1_tg);
    mpz_clear(q);

    return res;


}

void bts2target(uint32_t bts, mpz_t tg)
{
    uint8_t ep = bts >> 24;
    uint32_t mt = bts & 0xffffff;

    mpz_ui_pow_ui(tg, 2, 8 * (ep - 3));
    mpz_mul_ui(tg, tg, mt);
}

