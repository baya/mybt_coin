#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "varint.h"
#include "beej_pack.h"
#include "kyk_utils.h"


static size_t kyk_seri_txin(unsigned char *buf, struct kyk_txin *txin);
static size_t kyk_seri_txin_list(unsigned char *buf, struct kyk_txin *txin, size_t count);
static size_t kyk_seri_txout(unsigned char *buf, struct kyk_txout *txout);
size_t kyk_seri_txout_list(unsigned char *buf, struct kyk_txout *txout, size_t count);


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
