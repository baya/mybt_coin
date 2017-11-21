#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "varint.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "dbg.h"


static size_t kyk_seri_txin(unsigned char *buf, struct kyk_txin *txin);
static size_t kyk_seri_txin_list(unsigned char *buf, struct kyk_txin *txin, size_t count);
static size_t kyk_seri_txout(unsigned char *buf, struct kyk_txout *txout);
static size_t kyk_seri_txout_list(unsigned char *buf, struct kyk_txout *txout, size_t count);
static void kyk_free_txin(struct kyk_txin *txin);
static void kyk_free_txout(struct kyk_txout *txout);
static int kyk_make_coinbase_sc(struct kyk_txin *txin, const char *cb_note);


size_t kyk_seri_tx(unsigned char *buf, struct kyk_tx *tx)
{
    size_t size;
    size_t total = 0;

    size = beej_pack(buf, "<L", tx -> version);
    buf += size;
    total += size;

    size = kyk_pack_varint(buf, tx -> vin_sz);
    buf += size;
    total += size;

    size = kyk_seri_txin_list(buf, tx -> txin, tx -> vin_sz);
    buf += size;
    total += size;

    size = kyk_pack_varint(buf, tx -> vout_sz);
    buf += size;
    total += size;

    size = kyk_seri_txout_list(buf, tx -> txout, tx -> vout_sz);
    buf += size;
    total += size;

    size = beej_pack(buf, "<L", tx -> lock_time);
    buf += size;
    total += size;

    return total;
}

size_t kyk_seri_txin_list(unsigned char *buf, struct kyk_txin *txin, size_t count)
{
    size_t size = 0;
    size_t i = 0;
    size_t total = 0;

    for(i=0; i < count; i++){
	size = kyk_seri_txin(buf, txin);
	txin++;
	buf += size;
	total += size;
    }

    return total;
}

size_t kyk_seri_txout_list(unsigned char *buf, struct kyk_txout *txout, size_t count)
{
    size_t size = 0;
    size_t total = 0;
    size_t i = 0;

    for(i=0; i < count; i++){
	size = kyk_seri_txout(buf, txout);
	txout++;
	buf += size;
	total += size;
    }

    return total;
}


size_t kyk_seri_txin(unsigned char *buf, struct kyk_txin *txin)
{
    size_t size;
    size_t total = 0;

    size = kyk_reverse_pack_chars(buf, txin -> pre_txid, sizeof(txin->pre_txid));
    buf += size;
    total += size;

    size = beej_pack(buf, "<L", txin -> pre_tx_inx);
    buf += size;
    total += size;

    size = kyk_pack_varint(buf, txin -> sc_size);
    buf += size;
    total += size;

    size = kyk_pack_chars(buf, txin -> sc, txin -> sc_size);
    buf += size;
    total += size;

    size = beej_pack(buf, "<L", txin -> seq_no);
    buf += size;
    total += size;

    return total;
}

size_t kyk_seri_txout(unsigned char *buf, struct kyk_txout *txout)
{
    size_t size;
    size_t total = 0;

    size = beej_pack(buf, "<Q", txout -> value);
    buf += size;
    total += size;

    size = kyk_pack_varint(buf, txout -> sc_size);
    buf += size;
    total += size;

    size = kyk_pack_chars(buf, txout -> sc, txout -> sc_size);
    buf += size;
    total += size;

    return total;
}


struct kyk_txin *create_txin(const char *pre_txid,
			     uint32_t pre_tx_inx,
			     varint_t sc_size,
			     const char *sc,
			     uint32_t seq_no)
{
    struct kyk_txin *txin = malloc(sizeof(struct kyk_txin));
    if(txin == NULL){
	fprintf(stderr, "failed in malloc kyk_txin \n");
	exit(1);
    }

    if(hexstr_to_bytes(pre_txid, txin->pre_txid, 32) == -1){
	fprintf(stderr, "failed in setting pre_txid \n");
	exit(1);
    }

    txin->pre_tx_inx = pre_tx_inx;
    txin->sc_size = sc_size;
    txin->sc = malloc(sc_size * sizeof(unsigned char));
    if(hexstr_to_bytes(sc, txin->sc, sc_size) == -1){
	fprintf(stderr, "failed in setting txin sc \n");
	exit(1);
    }

    txin->seq_no = seq_no;

    return txin;
}

struct kyk_txout *create_txout(uint64_t value,
			       varint_t sc_size,
			       const char *sc)
{
    struct kyk_txout *txout = malloc(sizeof(struct kyk_txout));
    if(txout == NULL){
	fprintf(stderr, "failed in malloc kyk_txout \n");
	exit(1);
    }

    txout -> value = value;
    txout -> sc_size = sc_size;
    txout -> sc = malloc(sc_size * sizeof(unsigned char));
    
    if(hexstr_to_bytes(sc, txout->sc, sc_size) == -1){
	fprintf(stderr, "failed in setting txout sc \n");
	exit(1);
    }

    return txout;
}


void kyk_free_tx(struct kyk_tx *tx)
{
    if(tx -> txin) kyk_free_txin(tx -> txin);
    if(tx -> txout) kyk_free_txout(tx -> txout);
    if(tx) free(tx);
}

void kyk_free_txin(struct kyk_txin *txin)
{
    if(txin -> sc) free(txin -> sc);
    if(txin) free(txin);
}

void kyk_free_txout(struct kyk_txout *txout)
{
    if(txout -> sc) free(txout -> sc);
    if(txout) free(txout);
}

int kyk_make_coinbase_sc(struct kyk_txin *txin, const char *cb_note)
{
    unsigned char cb_tmp[1000] = {0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04};
    size_t cb_len = 7;
    size_t cb_note_len = strlen(cb_note);

    cb_tmp[7] = (uint8_t) cb_note_len;
    cb_len += 1;

    memcpy(cb_tmp + 8, cb_note, cb_note_len);
    cb_len += cb_note_len;

    txin -> sc_size = cb_len;
    check(txin -> sc_size < MAX_COINBASE_SC_LEN, "Failed to kyk_make_coinbase: over MAX_COINBASE_SC_LEN");

    txin -> sc = malloc(txin -> sc_size * sizeof(unsigned char));
    check(txin -> sc, "Failed to kyk_make_coinbase: malloc error");
    
    memcpy(txin -> sc, cb_tmp, txin -> sc_size);

    return 0;

error:
    return -1;
}

int kyk_make_coinbase_tx(struct kyk_tx** tx,
			 const char* note,
			 uint64_t outValue,
			 const uint8_t* pub,
			 size_t pub_len
    )
{
    struct kyk_txin* txin;
    struct kyk_txout* txout;
    struct kyk_tx* txcpy = NULL;
    struct kyk_buff* pbk_sc = NULL;
    int res = -1;

    check(tx, "Failed to kyk_make_coinbase_tx: tx can not be NULL");

    txcpy = (struct kyk_tx*)calloc(1, sizeof(struct kyk_tx));
    check(txcpy, "Failed to kyk_make_coinbase_tx: tx calloc error");

    txcpy -> version = 1;
    txcpy -> vin_sz = 1;
    txcpy -> lock_time = 0;
    txcpy -> txin = calloc(txcpy -> vin_sz, sizeof(struct kyk_txin));
    check(txcpy -> txin, "Failed to kyk_make_coinbase_tx: txin calloc error");
    
    txcpy -> vout_sz = 1;
    txcpy -> txout = calloc(txcpy -> vout_sz, sizeof(struct kyk_txout));
    check(txcpy -> txout, "Failed to kyk_make_coinbase_tx: txout calloc error");
    
    txin = txcpy -> txin;
    txout =txcpy -> txout;

    memset(txin -> pre_txid, KYK_COINBASE_PRE_TX_BYTE, sizeof(txin -> pre_txid));
    txin -> pre_tx_inx = KYK_COINBASE_PRE_TX_INX;
    kyk_make_coinbase_sc(txin, note);
    
    txin -> seq_no = KYK_COINBASE_SEQ_NO;
    txout -> value = outValue;

    /* addr = make_address_from_pem(GENS_PEM); */

    res = build_p2pkh_sc_from_pubkey(pub, pub_len, &pbk_sc);
    check(res == 0, "Failed to kyk_make_coinbase_tx: build_p2pkh_sc_from_pubkey error");

    txout -> sc_size = pbk_sc -> len;
    txout -> sc = calloc(txout -> sc_size, sizeof(uint8_t));
    check(txout -> sc, "Failed to kyk_make_coinbase_tx: calloc error");
    memcpy(txout -> sc, pbk_sc -> base, txout -> sc_size);

    free_kyk_buff(pbk_sc);

    *tx = txcpy;

    return 0;

error:
    if(pbk_sc) free_kyk_buff(pbk_sc);
    return -1;

}

