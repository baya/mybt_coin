#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "kyk_ser.h"
#include "kyk_utils.h"


int main()
{
    uint8_t buf[1000];
    size_t buf_len = 0;
    size_t len = 0;
    uint8_t *buf_cpy = buf;

    kyk_tx_inc_ser(&buf_cpy, "version-no", 2);
    
    kyk_tx_inc_ser(&buf_cpy, "in-counter", 1);


    /* len = kyk_tx_ser(buf_cpy, "version-no", 2); */
    /* buf_cpy += len; */
    
    /* len = kyk_tx_ser(buf_cpy, "in-counter", 1); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "pre-tx-hash:hex", "b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea"); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "pre-txout-inx", 1); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "txout-sc-len", 0x19); */
    /* buf_cpy += len; */
    
    /* len = kyk_tx_ser(buf_cpy, "txout-sc-pubkey:hex", "76a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88ac"); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "seq-no", 0xfeffffff); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "out-counter", 1); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "txout-value", 49500); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "txout-sc-len", 0x19); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "txout-sc-pubkey:hex", "76a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac"); */
    /* buf_cpy += len; */

    /* len = kyk_tx_ser(buf_cpy, "lock-time", 461576); */
    /* buf_cpy += len; */

    buf_len = buf_cpy - buf;

    kyk_print_hex("Tx Ser ", buf, buf_len);
}
