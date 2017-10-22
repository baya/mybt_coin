#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <openssl/pem.h>

#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_address.h"

#define SC_PUBKEY_LEN 1000
#define KYK_TX_BUF_LEN 10000

int get_priv_from_pem(uint8_t *priv, const char *pem_file_name);
void make_coinbase(struct kyk_txin *txin, const char *cb_note);

int main()
{
    uint8_t tx_buf[KYK_TX_BUF_LEN];
    size_t tx_buf_len;
    
    struct kyk_tx tx0;
    struct kyk_txin *txin;
    struct kyk_txout *txout;

    char *cb = "From 4/Sept/2017 China start suppressing the Bitcoin";
    
    uint8_t priv[32];
    char *pem_name = "kyk-gens-priv.pem";
    char *addr;
    uint8_t sc_pbk[SC_PUBKEY_LEN];
    size_t sc_pbk_len;

    FILE *fp = fopen("gens-tx.bin", "wb");
    size_t wsize;

    struct kyk_hash *txid;


    tx0.version = 1;
    tx0.vin_sz = 1;
    tx0.lock_time = 0;
    tx0.txin = malloc(tx0.vin_sz * sizeof(struct kyk_txin));
    tx0.vout_sz = 1;
    tx0.txout = malloc(tx0.vout_sz * sizeof(struct kyk_txout));
    txin = tx0.txin;
    txout = tx0.txout;

    memset(txin -> pre_txid, 0x00, sizeof(txin -> pre_txid));
    txin -> pre_tx_inx = 0xffffffff;
    make_coinbase(txin, cb);
    
    txin -> seq_no = 0xFFFFFFFF;

    txout -> value = 10000000000;
    

    get_priv_from_pem(priv, pem_name);
    addr = kyk_make_address(priv);
    sc_pbk_len = p2pkh_sc_from_address(sc_pbk, addr);
    txout -> sc_size = sc_pbk_len;
    txout -> sc = sc_pbk;

    tx_buf_len = kyk_seri_tx(tx_buf, &tx0);

    wsize = fwrite(tx_buf, sizeof(tx_buf[0]), tx_buf_len, fp);
    if(wsize == tx_buf_len){
	printf("saved gens tx to gens-tx.bin successfully\n");
    }

    txid = kyk_inver_hash((char *)tx_buf, tx_buf_len);
    kyk_print_hex("Txid ", txid -> body, txid -> len);

    kyk_print_hex("coinbase ", txin -> sc, txin -> sc_size);
    
}

void make_coinbase(struct kyk_txin *txin, const char *cb_note)
{
    unsigned char cb_tmp[1000] = {0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04};
    size_t cb_len = 7;
    size_t cb_note_len = strlen(cb_note);

    cb_tmp[7] = (uint8_t) cb_note_len;
    cb_len += 1;

    memcpy(cb_tmp + 8, cb_note, cb_note_len);
    cb_len += cb_note_len;

    txin -> sc_size = cb_len;

    txin -> sc = malloc(txin -> sc_size * sizeof(unsigned char));
    memcpy(txin -> sc, cb_tmp, txin -> sc_size);
}

int get_priv_from_pem(uint8_t *priv, const char *pem_file_name)
{
    EVP_PKEY *evp_key;
    EC_KEY *ec_key;
    const BIGNUM *priv_bn;
    char *addr;

    FILE *fp = fopen(pem_file_name, "r");
    if(!fp){
	perror("Pem File opening failed");
        return EXIT_FAILURE;
    }
    evp_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!evp_key)	{
	fprintf(stderr, "Unable to read pem\n");
	return -1;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(priv_bn, priv);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    fclose(fp);

    return 1;
}
