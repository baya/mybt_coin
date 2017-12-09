#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kyk_utils.h"
#include "kyk_difficulty.h"
#include "dbg.h"

#include <openssl/bn.h>


/* When a variable of type mpz_t is used as a function parameter, it's effectively a call-by-reference, meaning anything the function does to it will be be done to the original in the caller */
void kyk_bts2target(uint32_t bts, mpz_t tg)
{
    uint8_t ep = bts >> 24;
    uint32_t mt = bts & 0x007fffff;

    if(ep <= 3){
	mt >>= 8 * (3 - ep);
	mpz_set_ui(tg, mt);
    } else {
	/* mpz_set_ui(tg, uint64_t(mt)); */
	mpz_ui_pow_ui(tg, 2, 8 * (ep - 3));
	mpz_mul_ui(tg, tg, mt);
    }

}

/* https://bitcoin.stackexchange.com/questions/2924/how-to-calculate-new-bits-value */
int kyk_target2bts(mpz_t tg, uint32_t* new_bts)
{
    uint8_t digest[33];
    uint32_t bts;
    uint32_t dlen;
    int i = 0;


    mpz_export(digest+1, (size_t*)&dlen, 1, sizeof(*digest), 1, 0, tg);

    if(digest[1] > 0x7f){
    	dlen += 1;
    	i = 0;
    } else {
    	/* if The first digit is not greater than 0x7f, we don't prepend a zero digit */
    	i = 1;
    }
    bts = dlen << 24;

    bts |= (digest[i] << 16);
    bts |= (digest[i+1] << 8);
    bts |= (digest[i+2] << 0);

   
    *new_bts = bts;

    return 0;
    
}


/* NextTarget = (PrevTarget * T) / (2016 * 600) */
int kyk_cal_next_work_req(uint32_t prev_timespan,
			     uint32_t target_timespan,
			     uint32_t prev_bts,
			     uint32_t* next_bts)
{
    mpz_t prev_tg;
    mpz_t next_tg;
    mpz_t q;
    

    if(prev_timespan < target_timespan / 4){
	prev_timespan = target_timespan / 4;
    }

    if(prev_timespan > target_timespan * 4){
	prev_timespan = target_timespan * 4;
    }

    mpz_init(next_tg);
    
    mpz_init(q);
    mpz_set_ui(q, target_timespan);
    
    mpz_init(prev_tg);
    kyk_bts2target(prev_bts, prev_tg);

    mpz_mul_ui(prev_tg, prev_tg, prev_timespan);
    mpz_cdiv_q(next_tg, prev_tg, q);

    kyk_target2bts(next_tg, next_bts);

    mpz_clear(prev_tg);
    mpz_clear(next_tg);
    mpz_clear(q);

    return 0;
    
}


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
