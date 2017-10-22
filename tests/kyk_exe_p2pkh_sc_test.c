#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_ser.h"

#define KYK_SC_PUBK_MAX_LEN 1000
#define KYK_SC_MAX_LEN 2000

int main()
{
    unsigned char sc_pubk[KYK_SC_PUBK_MAX_LEN];
    char *addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    char *sc_sig_hex = "47304402207f9837b1e2a45e1e7f8054cb841af7e62fd40bf1a9becbebf38e9befe605905b02201fd0d11e48183c0b812f5fdecc36c0caf6fd1184d3ebd85192d711824c02f015014104c4ae8574bd6a8a89af1fad3a945b14f6745cc998f544ab193ffc568b33598f2191dd06dd37c3b971f6f8452e84d86bcb82c29d7fb8787723ca08216a24051af3";
    uint8_t *sc_sig;
    uint8_t sc[KYK_SC_MAX_LEN];
    size_t sc_pubk_len, sc_sig_len, sc_len;
    int verified = 0;

    /* https://blockexplorer.com/api/rawtx/1e4f607d33175aa3b0a854c7d494ee0eb0ac3f0fc0a759ad1ddf88efbe8cd37d */
    /* unsig_tx -> 0200000001b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea010000001976a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88acfeffffff015cc10000000000001976a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac080b0700 */
    uint8_t unsig_tx[1000];
    uint8_t *utx_cpy = unsig_tx;

    kyk_tx_inc_ser(&utx_cpy, "version-no", 2);
    
    kyk_tx_inc_ser(&utx_cpy, "in-counter", 1);

    kyk_tx_inc_ser(&utx_cpy, "pre-tx-hash:hex", "b636c0cd9a296f29d1b4760c291c3044422f12eab2d7c363ff5f0b90b68aa9ea");

    kyk_tx_inc_ser(&utx_cpy, "pre-txout-inx", 1);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-len", 0x19);
    
    kyk_tx_inc_ser(&utx_cpy, "txout-sc-pubkey:hex", "76a914c73e88dfa45a940bbec4f5654b910254e8b5d7be88ac");

    kyk_tx_inc_ser(&utx_cpy, "seq-no", 0xfeffffff);

    kyk_tx_inc_ser(&utx_cpy, "out-counter", 1);

    kyk_tx_inc_ser(&utx_cpy, "txout-value", 49500);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-len", 0x19);

    kyk_tx_inc_ser(&utx_cpy, "txout-sc-pubkey:hex", "76a9140b5b85548100b98164f7748f931b66eb1b1b0ec888ac");

    kyk_tx_inc_ser(&utx_cpy, "lock-time", 461576);



    /* 从 hex 字符串直接拷贝 scriptSig 到内存 */
    sc_sig = kyk_alloc_hex(sc_sig_hex, &sc_sig_len);

    /* 从比特币地址中提取 pay-to-pubkey-hash 脚本 */
    sc_pubk_len = p2pkh_sc_from_address(sc_pubk, addr);

    /* 合并 scriptSig 和 scriptPubKey 为一个脚本 */
    sc_len = kyk_combine_sc(sc, sc_sig, sc_sig_len, sc_pubk, sc_pubk_len);

    verified = kyk_run_sc(sc, sc_len, unsig_tx, utx_cpy - unsig_tx);

    printf("script verified: %s\n", verified == 1 ? "true" : "false");

    free(sc_sig);
}
