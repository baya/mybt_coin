#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "kyk_block.h"
#include "kyk_utxo.h"
#include "varint.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_buff.h"
#include "kyk_sha.h"
#include "kyk_address.h"
#include "dbg.h"


static size_t kyk_seri_txin(unsigned char *buf, struct kyk_txin *txin);
static size_t kyk_seri_txin_list(unsigned char *buf, struct kyk_txin *txin, size_t count);
static size_t kyk_seri_txout(unsigned char *buf, struct kyk_txout *txout);
static size_t kyk_seri_txout_list(unsigned char *buf, struct kyk_txout *txout, size_t count);
static int kyk_make_coinbase_sc(struct kyk_txin *txin, const char *cb_note);
static int get_txin_size(struct kyk_txin* txin, size_t* txin_size);
static int get_txout_size(struct kyk_txout* txout, size_t* txout_size);
static int placehold_txin_with_txout(struct kyk_txin* txin, const struct kyk_txout* txout);
static int set_all_txins_sc_to_blank(struct kyk_tx* tx);

int kyk_deseri_txin_list(struct kyk_txin* txin_list,
			 size_t txin_count,
			 const uint8_t* buf,
			 size_t* byte_num);

int kyk_deseri_txin(struct kyk_txin* txin,
		    const uint8_t* buf,
		    size_t* byte_num);


int kyk_deseri_txout_list(struct kyk_txout* txout_list,
			  size_t txout_count,
			  const uint8_t* buf,
			  size_t* byte_num);

int kyk_deseri_txout(struct kyk_txout* txout,
		     const uint8_t* buf,
		     size_t* byte_num);

void kyk_print_txout(const struct kyk_txout* txout)
{
    printf("txout -> value: %llu\n", txout -> value);
    printf("txout -> sc_size: %llu\n", txout -> sc_size);
    kyk_print_hex("txout -> sc", txout -> sc, txout -> sc_size);
}

void kyk_print_tx_list(const struct kyk_tx* tx_list, size_t tx_count)
{
    const struct kyk_tx* tx = NULL;
    size_t i = 0;

    for(i = 0; i < tx_count; i++){
	tx = tx_list + i;
	kyk_print_tx(tx);
    }
}

void kyk_print_tx(const struct kyk_tx* tx)
{
    varint_t i = 0;
    printf("tx -> version: %u\n", tx -> version);
    printf("tx -> vin_sz: %llu\n", tx -> vin_sz);
    for(i = 0; i < tx -> vin_sz; i++){
	kyk_print_txin(tx -> txin + i);
    }
    printf("tx -> vout_sz: %llu\n", tx -> vout_sz);
    for(i = 0; i < tx -> vout_sz; i++){
	kyk_print_txout(tx -> txout + i);
    }

    printf("tx -> lock_time: %u\n", tx -> lock_time);
}

void kyk_print_txin(const struct kyk_txin* txin)
{
    kyk_print_hex("txin -> pre_txid", txin -> pre_txid, sizeof(txin -> pre_txid));
    printf("txin -> pre_txout_inx: %u\n", txin -> pre_txout_inx);
    printf("txin -> sc_size: %llu\n", txin -> sc_size);
    kyk_print_hex("txin -> sc", txin -> sc, txin -> sc_size);
    printf("txin -> seq_no: %0x\n", txin -> seq_no);
}

int kyk_tx_hash256(uint8_t* digest, const struct kyk_tx* tx)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    size_t tx_size = 0;
    int res = -1;

    check(digest, "Failed to kyk_tx_hash256: digest is NULL");
    check(tx, "Failed to kyk_tx_hash256: tx is NULL");

    res = kyk_get_tx_size(tx, &tx_size);
    check(res == 0, "Failed to kyk_tx_hash256: kyk_get_tx_size failed");
    check(tx_size > 0, "Failed to kyk_tx_hash256: kyk_get_tx_size failed");

    buf = calloc(tx_size, sizeof(*buf));
    check(buf, "Failed to kyk_tx_hash256: buf calloc failed");
    len = kyk_seri_tx((unsigned char*)buf, tx);
    check(len == tx_size, "Failed to kyk_tx_hash256: kyk_seri_tx failed");
    
    kyk_dgst_hash256(digest, buf, tx_size);
    kyk_reverse(digest, SHA256_DIGEST_LENGTH);

    return 0;
    
error:

    return -1;
}

int kyk_copy_new_tx(struct kyk_tx** new_tx, const struct kyk_tx* src_tx)
{
    struct kyk_tx* tx = NULL;
    int res = -1;
    
    check(new_tx, "Failed to kyk_copy_new_tx: new_tx is NULL");
    check(src_tx, "Failed to kyk_copy_new_tx: src_tx is NULL");

    tx = calloc(1, sizeof(*tx));
    check(tx, "Failed to kyk_copy_new_tx: tx calloc failed");

    res = kyk_copy_tx(tx, src_tx);
    check(res == 0, "Failed to kyk_copy_new_tx: kyk_copy_tx failed");

    *new_tx = tx;

    return 0;
    
error:
    if(tx) kyk_free_tx(tx);
    return -1;
}

int kyk_copy_tx(struct kyk_tx* dest_tx, const struct kyk_tx* src_tx)
{
    size_t i = 0;
    int res = -1;
    
    check(dest_tx, "Failed to kyk_copy_tx: dest_tx is NULL");
    check(src_tx, "Failed to kyk_copy_tx: src_tx is NULL");

    dest_tx -> version = src_tx -> version;
    dest_tx -> vin_sz = src_tx -> vin_sz;
    dest_tx -> txin = calloc(dest_tx -> vin_sz, sizeof(struct kyk_txin));
    check(dest_tx -> txin, "Failed to kyk_copy_tx: calloc dest_tx -> txin failed");
    for(i = 0; i < src_tx -> vin_sz; i++){
	res = kyk_copy_txin(dest_tx -> txin + i, src_tx -> txin + i);
	check(res == 0, "failed to kyk_copy_tx: kyk_copy_txin failed");
    }

    dest_tx -> vout_sz = src_tx -> vout_sz;
    dest_tx -> txout = calloc(dest_tx -> vout_sz, sizeof(struct kyk_txout));
    check(dest_tx -> txout, "Failed to kyk_copy_tx: calloc dest_tx -> txout failed");
    for(i = 0; i < src_tx -> vout_sz; i++){
	res = kyk_copy_txout(dest_tx -> txout + i, src_tx -> txout + i);
	/* res = kyk_add_txout(dest_tx, i, txout +i); */
	check(res == 0, "failed to kyk_copy_tx: kyk_add_txout failed");
    }

    dest_tx -> lock_time = src_tx -> lock_time;

    return 0;
error:

    return -1;
}

int kyk_copy_txin(struct kyk_txin* txin, const struct kyk_txin* src_txin)
{
    check(txin, "Failed to kyk_copy_txin: txin is NULL");
    check(txin -> sc == NULL, "Failed to kyk_copy_txin: txin -> sc should be NULL");
    check(src_txin, "Failed to kyk_copy_txin: src_txin is NULL");

    memcpy(txin -> pre_txid, src_txin -> pre_txid, sizeof(txin -> pre_txid));

    txin -> pre_txout_inx = src_txin -> pre_txout_inx;
    txin -> sc_size = src_txin -> sc_size;

    txin -> sc = calloc(txin -> sc_size, sizeof(*txin -> sc));
    check(txin -> sc, "Failed to kyk_copy_txin: txin -> sc calloc failed");

    memcpy(txin -> sc, src_txin -> sc, txin -> sc_size);
    txin -> seq_no = src_txin -> seq_no;

    return 0;
    
error:
    if(txin -> sc) free(txin -> sc);
    return -1;
}

int kyk_copy_txout(struct kyk_txout* txout, const struct kyk_txout* src_txout)
{
    check(txout, "Failed to kyk_copy_txout: txout is NULL");
    check(txout -> sc == NULL, "Failed to kyk_copy_txout: txout -> sc should be NULL");
    check(src_txout, "Failed to kyk_copy_txout: src_txout is NULL");

    txout -> value = src_txout -> value;
    txout -> sc_size = src_txout -> sc_size;
    
    txout -> sc = calloc(txout -> sc_size, sizeof(*txout -> sc));
    check(txout -> sc, "Failed to kyk_copy_txout: txout -> sc calloc failed");
    
    memcpy(txout -> sc, src_txout -> sc, txout -> sc_size);

    return 0;
    
error:
    if(txout -> sc) free(txout -> sc);
    return -1;
}


int kyk_get_tx_size(const struct kyk_tx* tx, size_t* tx_size)
{
    size_t len = 0;
    size_t i = 0;
    int res = -1;
    struct kyk_txin* txin = NULL;
    struct kyk_txout* txout = NULL;

    check(tx, "Failed to kyk_get_tx_size: tx is NULL");
    check(tx_size, "Failed to kyk_get_tx_size: tx_size is NULL");
    
    len += sizeof(tx -> version);
    len += get_varint_size(tx -> vin_sz);
    check(tx -> txin, "Failed to kyk_get_tx_size: tx -> txin is NULL");
    
    for(i = 0; i < tx -> vin_sz; i++){
	size_t txin_size = 0;
	txin = tx -> txin + i;
	res = get_txin_size(txin, &txin_size);
	check(res == 0, "Failed to kyk_get_tx_size: get_txin_size failed");

	len += txin_size;
    }

    len += get_varint_size(tx -> vout_sz);

    check(tx -> txout, "Failed to kyk_get_tx_size: tx -> txout is NULL");
    for(i = 0; i < tx -> vout_sz; i++){
	size_t txout_size = 0;
	txout = tx -> txout + i;
	res = get_txout_size(txout, &txout_size);
	check(res == 0, "Failed to kyk_get_tx_size: get_txout_size failed");

	len += txout_size;
    }

    len += sizeof(tx -> lock_time);

    *tx_size = len;

    return 0;
    
error:

    return -1;
    
}

int get_txin_size(struct kyk_txin* txin, size_t* txin_size)
{
    size_t len = 0;
    len += sizeof(txin -> pre_txid);
    len += sizeof(txin -> pre_txout_inx);
    check(txin -> sc_size >= 0, "Failed to get_txin_size: txin -> sc_size is invalid");
    len += get_varint_size(txin -> sc_size);
    len += txin -> sc_size;
    len += sizeof(txin -> seq_no);

    *txin_size = len;

    return 0;

error:

    return -1;
}

int get_txout_size(struct kyk_txout* txout, size_t* txout_size)
{
    size_t len = 0;
    len += sizeof(txout -> value);
    check(txout -> sc_size >= 1, "Failed to get_txout_size: txout -> sc_size is invalid");
    len += get_varint_size(txout -> sc_size);
    len += txout -> sc_size;

    *txout_size = len;

    return 0;

error:
    return -1;
}

int kyk_seri_tx_list(struct kyk_bon_buff* buf_list,
		     const struct kyk_tx* tx_list,
		     size_t tx_count)
{
    struct kyk_bon_buff* buf = NULL;
    const struct kyk_tx* tx = NULL;
    size_t i = 0;
    size_t len = 0;
    size_t tx_size = 0;
    int res = -1;

    for(i = 0; i < tx_count; i++){
	buf = buf_list + i;
	check(buf, "Failed to kyk_seri_tx_list: buf is NULL");	
	tx = &tx_list[i];
	check(tx, "Failed to kyk_seri_tx_list: tx is NULL");
	if(buf -> base) free(buf -> base);
	res = kyk_get_tx_size(tx, &tx_size);
	check(res == 0, "Failed to kyk_seri_tx_list: kyk_get_tx_size failed");
	buf -> base = calloc(tx_size, sizeof(*buf -> base));
	check(buf -> base, "Failed to kyk_seri_tx_list: calloc buf -> base failed");
	len = kyk_seri_tx(buf -> base, tx);
	check(len > 0, "Failed to kyk_seri_tx_list: kyk_seri_tx failed");
	buf -> len = len;
    }
    
    return 0;

error:

    return -1;
}

int kyk_seri_tx_to_new_buf(const struct kyk_tx* tx,
			   uint8_t** new_buf,
			   size_t* buf_len)
{
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    size_t tx_size = 0;
    size_t blen = 0;
    int res = -1;

    check(tx, "Failed to kyk_seri_tx_to_new_buf: tx is NULL");
    check(new_buf, "Failed to kyk_seri_tx_to_new_buf: new_buf is NULL");

    res = kyk_get_tx_size(tx, &tx_size);
    check(res == 0, "Failed to kyk_seri_tx_to_new_buf: kyk_get_tx_size failed");

    buf = calloc(tx_size, sizeof(*buf));
    check(buf, "Failed to kyk_seri_tx_to_new_buf: buf calloc failed");

    bufp = buf;

    blen = kyk_seri_tx(bufp, tx);
    check(blen == tx_size, "Failed to kyk_seri_tx_to_new_buf: kyk_seri_tx failed");

    if(buf_len){
	*buf_len = blen;
    }

    *new_buf = buf;

    return 0;
    
error:
    if(buf) free(buf);
    return -1;
}


size_t kyk_seri_tx(unsigned char *buf, const struct kyk_tx *tx)
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

    size = kyk_reverse_pack_chars(buf, txin -> pre_txid, sizeof(txin -> pre_txid));
    buf += size;
    total += size;

    size = beej_pack(buf, "<L", txin -> pre_txout_inx);
    buf += size;
    total += size;

    if(txin -> sc_size == 0){
	*buf = 0x00;
	buf += 1;
	total += 1;
    } else {
	size = kyk_pack_varint(buf, txin -> sc_size);
	buf += size;
	total += size;
    }

    if(txin -> sc_size > 0){
	size = kyk_pack_chars(buf, txin -> sc, txin -> sc_size);
	buf += size;
	total += size;
    }

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

int kyk_add_txin(struct kyk_tx* tx,
		 size_t inx,
		 const struct kyk_txin* out_txin)
{
    check(tx, "Failed to kyk_add_txin: tx is NULL");
    check(inx >= 0, "Failed to kyk_add_txin: inx is invalid");
    check(out_txin, "Failed to kyk_add_txin: out_txin is NULL");

    struct kyk_txin* txin = NULL;

    txin = tx -> txin + inx;
    check(txin, "Failed to kyk_add_txin: txin out of memory");

    memcpy(txin -> pre_txid, out_txin -> pre_txid, sizeof(txin -> pre_txid));
    
    txin -> pre_txout_inx = out_txin -> pre_txout_inx;
    txin -> sc_size = out_txin -> sc_size;
    
    if(txin -> sc){
	free(txin -> sc);
	txin -> sc = NULL;
    }
    txin -> sc = calloc(txin -> sc_size, sizeof(unsigned char));
    check(txin -> sc, "Failed to kyk_add_txin: txin -> sc is NULL");
    
    memcpy(txin -> sc, out_txin -> sc, txin -> sc_size);
    txin -> seq_no = out_txin -> seq_no;

    return 0;


error:

    return -1;
}

int kyk_add_txout(struct kyk_tx* tx,
		  size_t inx,
		  const struct kyk_txout* out_txout)
{
    check(tx, "Failed to kyk_add_txout: tx is NULL");
    check(inx >= 0, "Failed to kyk_add_txout: inx is invalid");
    check(out_txout, "Failed to kyk_add_txout: out_txout is NULL");
    check(out_txout -> sc_size > 0, "Failed to kyk_add_txout: out_txout -> sc_size is inivalid");

    struct kyk_txout* txout = NULL;

    txout = tx -> txout + inx;
    check(txout, "Failed to kyk_add_txin: txout out of memory");

    txout -> value = out_txout -> value;
    txout -> sc_size = out_txout -> sc_size;

    if(txout -> sc) free(txout -> sc);
    txout -> sc = calloc(txout -> sc_size, sizeof(unsigned char));
    check(txout -> sc, "Failed to kyk_add_txout: txout -> sc calloc failed");
    memcpy(txout -> sc, out_txout -> sc, txout -> sc_size);

    return 0;
 
error:

    return -1;

}


struct kyk_txin *create_txin(const char *pre_txid,
			     uint32_t pre_txout_inx,
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

    txin->pre_txout_inx = pre_txout_inx;
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


/* have some memory leaks, to-do refactor it */
void kyk_free_tx(struct kyk_tx *tx)
{
    if(tx){
	if(tx -> txin) {
	    kyk_free_txin_list(tx -> txin, tx -> vin_sz);
	    tx -> txin = NULL;
	}
	if(tx -> txout) {
	    kyk_free_txout_list(tx -> txout, tx -> vout_sz);
	    tx -> txout = NULL;
	}
	
	free(tx);
    }
}

void kyk_free_txin(struct kyk_txin* txin)
{
    if(txin){
	if(txin -> sc) {
	    free(txin -> sc);
	    txin -> sc = NULL;
	}
	free(txin);
	txin = NULL;
    }

}

void kyk_free_txout(struct kyk_txout *txout)
{
    if(txout) {
	if(txout -> sc){
	    free(txout -> sc);
	    txout -> sc = NULL;
	}
    
	free(txout);
	txout = NULL;
    }
}

void kyk_free_tx_list(struct kyk_tx* tx_list, size_t tx_count)
{
    size_t i = 0;
    if(tx_list){
	for(i = 1; i < tx_count; i++){
	    kyk_free_tx(tx_list + i);
	}
	kyk_free_tx(tx_list);
    }
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

int kyk_make_coinbase_tx(struct kyk_tx** cb_tx,
			 const char* note,
			 uint64_t outValue,
			 const uint8_t* pub,
			 size_t pub_len
    )
{
    struct kyk_tx* tx = NULL;
    struct kyk_txin* txin = NULL;
    struct kyk_txout* txout = NULL;
    struct kyk_buff* pbk_sc = NULL;
    int res = -1;

    check(cb_tx, "Failed to kyk_make_coinbase_tx: cb_tx is NULL");

    tx = calloc(1, sizeof(*tx));
    check(tx, "Failed to kyk_make_coinbase_tx: tx calloc failed");

    tx -> version = 1;
    tx -> vin_sz = 1;
    tx -> lock_time = 0;
    tx -> txin = calloc(tx -> vin_sz, sizeof(struct kyk_txin));
    check(tx -> txin, "Failed to kyk_make_coinbase_tx: tx -> txin calloc failed");
    
    tx -> vout_sz = 1;
    tx -> txout = calloc(tx -> vout_sz, sizeof(struct kyk_txout));
    check(tx -> txout, "Failed to kyk_make_coinbase_tx: tx -> txout calloc failed");
    
    txin = tx -> txin;
    txout = tx -> txout;

    memset(txin -> pre_txid, KYK_COINBASE_PRE_TX_BYTE, sizeof(txin -> pre_txid));
    txin -> pre_txout_inx = COINBASE_INX;
    kyk_make_coinbase_sc(txin, note);
    
    txin -> seq_no = KYK_COINBASE_SEQ_NO;
    txout -> value = outValue;

    res = build_p2pkh_sc_from_pubkey(pub, pub_len, &pbk_sc);
    check(res == 0, "Failed to kyk_make_coinbase_tx: build_p2pkh_sc_from_pubkey error");

    txout -> sc_size = pbk_sc -> len;
    txout -> sc = calloc(txout -> sc_size, sizeof(*txout -> sc));
    check(txout -> sc, "Failed to kyk_make_coinbase_tx: calloc failed");
    memcpy(txout -> sc, pbk_sc -> base, txout -> sc_size);

    *cb_tx = tx;

    free_kyk_buff(pbk_sc);
    pbk_sc = NULL;

    return 0;

error:
    if(tx) kyk_free_tx(tx);
    if(pbk_sc) {
	free_kyk_buff(pbk_sc);
	pbk_sc = NULL;
    }
    return -1;

}

struct kyk_tx* kyk_create_tx(uint32_t version,
			     varint_t vin_sz,
			     varint_t vout_sz,
			     uint32_t lock_time
    )
{
    struct kyk_tx* tx = NULL;
    tx = calloc(1, sizeof(struct kyk_tx));
    check(tx, "Failed to kyk_create_tx: calloc failed");

    tx -> version = version;
    
    check(vin_sz >= 1, "Failed to kyk_create_tx: vin_sz should be greater than 1");
    tx -> vin_sz = vin_sz;
    tx -> txin = calloc(tx -> vin_sz, sizeof(struct kyk_txin));
    check(tx -> txin, "Failed to kyk_create_tx: calloc txin failed");

    check(vout_sz >= 1, "Failed to kyk_create_tx: vout_sz should be greater than 1");
    tx -> vout_sz = vout_sz;
    tx -> txout = calloc(tx -> vout_sz, sizeof(struct kyk_txout));
    check(tx -> txout, "Failed to kyk_create_tx: calloc txout failed");

    tx -> lock_time = lock_time;

    return tx;
    
error:

    return NULL;
}


int kyk_deseri_tx_list(struct kyk_tx* tx_list,
		       size_t tx_count,
		       const uint8_t* buf,
		       size_t* byte_num)
{
    struct kyk_tx* tx = NULL;
    size_t len = 0;
    const unsigned char* bufp = (const unsigned char*)buf;
    int res = -1;
    size_t i = 0;

    check(tx_list != NULL, "Failed to kyk_deseri_tx_list: tx_list is NULL");
    check(tx_count >= 1, "Failed to kyk_deseri_tx_list: tx_count is invalid");
    check(buf != NULL, "Failed to kyk_deseri_tx_list: buf is NULL");
    

    for(i = 0; i < tx_count; i++){
	tx = tx_list + i;
	res = kyk_deseri_tx(tx, bufp, &len);
	check(res == 0, "Failed to kyk_deseri_tx_list: kyk_deseri_tx failed");
	bufp += len;
    }

    if(byte_num){
	*byte_num = bufp - buf;
    }
    

    return 0;
    
error:

    return -1;
}

int kyk_deseri_new_tx(struct kyk_tx** new_tx,
		      const uint8_t* buf,
		      size_t* byte_num)
{
    struct kyk_tx* tx = NULL;
    int res = -1;

    check(new_tx, "Failed to kyk_deseri_new_tx: new_tx is NULL");
    check(buf, "Failedt to kyk_deseri_new_tx: buf is NULL");

    tx = calloc(1, sizeof(*tx));
    check(tx, "Failed to kyk_dseri_new_tx: tx calloc failed");

    res = kyk_deseri_tx(tx, buf, byte_num);
    check(res == 0, "Failed to kyk_deseri_new_tx: kyk_deseri_tx failed");

    *new_tx = tx;

    return 0;
    
error:
    if(tx) kyk_free_tx(tx);
    return -1;
}

int kyk_deseri_tx(struct kyk_tx* tx,
		  const uint8_t* buf,
		  size_t* byte_num)
{
    size_t len = 0;
    unsigned char* bufp = (unsigned char*)buf;
    int res = -1;
    int arg_checked = 0;

    check(tx != NULL, "Failed to kyk_deseri_tx: tx is NULL");
    check(tx -> txin == NULL, "Failed to kyk_deseri_tx: tx -> txin is not NULL");
    check(tx -> txout == NULL, "Failed to kyk_deseri_tx: tx -> txout is not NULL");
    check(buf != NULL,  "Failed to kyk_deseri_tx: buf is NULL");
    arg_checked = 1;
    
    beej_unpack(bufp, "<L", &tx -> version);
    bufp += sizeof(tx -> version);

    len = kyk_unpack_varint(bufp, &tx -> vin_sz);
    check(len > 0, "Failed to kyk_deseri_tx: kyk_unpack_varint failed");
    bufp += len;

    tx -> txin = calloc(tx -> vin_sz, sizeof(struct kyk_txin));
    check(tx -> txin, "Failed to kyk_deseri_tx: calloc tx -> txin failed");
    
    res = kyk_deseri_txin_list(tx -> txin, tx -> vin_sz, bufp, &len);
    check(res == 0, "Failed to kyk_deseri_tx: kyk_deseri_txin_list failed");
    bufp += len;

    len = kyk_unpack_varint(bufp, &tx -> vout_sz);
    check(len > 0, "Failed to kyk_deseri_tx: kyk_unpack_varint failed");
    bufp += len;

    tx -> txout = calloc(tx -> vout_sz, sizeof(struct kyk_txout));
    check(tx -> txout, "Failed to kyk_deseri_tx: calloc tx -> txout failed");
    res = kyk_deseri_txout_list(tx -> txout, tx -> vout_sz, bufp, &len);
    bufp += len;

    beej_unpack(bufp, "<L", &tx -> lock_time);
    bufp += sizeof(tx -> lock_time);

    if(byte_num){
	*byte_num = bufp - buf;
    }
    
    return 0;

error:
    if(arg_checked){
	if(tx -> txin) {
	    kyk_free_txin(tx -> txin);
	    tx -> txin = NULL;
	}
	if(tx -> txout) {
	    kyk_free_txout(tx -> txout);
	    tx -> txout = NULL;
	}
    }
    return -1;
}


int kyk_deseri_txin_list(struct kyk_txin* txin_list,
			 size_t txin_count,
			 const uint8_t* buf,
			 size_t* byte_num)
{
    unsigned char* bufp = NULL;
    struct kyk_txin* txin = NULL;
    int res = -1;
    size_t i = 0;
    size_t len = 0;

    check(txin_list, "Failed to kyk_deseri_txin_list: txin_list is NULL");
    check(buf, "Failed to kyk_deseri_txin_list: buf is NULL");

    bufp = (unsigned char*) buf;

    for(i = 0; i < txin_count; i++){
	txin = txin_list + i;
	res = kyk_deseri_txin(txin, bufp, &len);
	check(res == 0, "Failed to kyk_deseri_txin_list: kyk_deseri_txin failed");
	bufp += len;
    }

    *byte_num = bufp - buf;

    return 0;

error:

    return -1;
    
}


int kyk_deseri_txin(struct kyk_txin* txin,
		    const uint8_t* buf,
		    size_t* byte_num)
{
    unsigned char* bufp = NULL;
    size_t len = 0;
    int arg_checked = 0;
    
    check(txin, "Failed to kyk_deseri_txin: txin is NULL");
    check(txin -> sc == NULL, "Failed to kyk_deseri_txin: txin -> sc is not NULL");
    check(buf, "Failed to kyk_deseri_txin: buf is NULL");
    arg_checked = 1;
    

    bufp = (unsigned char*)buf;

    kyk_reverse_pack_chars(txin -> pre_txid, bufp, sizeof(txin -> pre_txid));
    bufp += sizeof(txin -> pre_txid);

    beej_unpack(bufp, "<L", &txin -> pre_txout_inx);
    bufp += sizeof(txin -> pre_txout_inx);


    len = kyk_unpack_varint(bufp, &txin -> sc_size);
    bufp += len;

    txin -> sc = calloc(txin -> sc_size, sizeof(*txin -> sc));
    check(txin -> sc, "Failed to kyk_deseri_txin: txin -> sc calloc failed");
    memcpy(txin -> sc, bufp, txin -> sc_size);
    bufp += txin -> sc_size;

    beej_unpack(bufp, "<L", &txin -> seq_no);
    bufp += sizeof(txin -> seq_no);

    *byte_num = bufp - buf;

    return 0;
    
error:
    if(arg_checked){
	if(txin -> sc) {
	    free(txin -> sc);
	    txin -> sc = NULL;
	}
    }
    return -1;
}


int kyk_deseri_txout_list(struct kyk_txout* txout_list,
			  size_t txout_count,
			  const uint8_t* buf,
			  size_t* byte_num)
{
    const unsigned char* bufp = NULL;
    struct kyk_txout* txout = NULL;
    int res = -1;
    size_t i = 0;
    size_t len = 0;

    check(txout_list, "Failed to kyk_deseri_txout_list: txout_list is NULL");
    check(buf, "Failed to kyk_deseri_txout_list: buf is NULL");

    bufp = (const unsigned char*) buf;

    for(i = 0; i < txout_count; i++){
	txout = txout_list + i;
	res = kyk_deseri_txout(txout, bufp, &len);
	check(res == 0, "Failed to kyk_deseri_txout_list: kyk_deseri_txout failed");
	bufp += len;
    }

    *byte_num = bufp - buf;

    return 0;

error:

    return -1;
    
}

int kyk_deseri_txout(struct kyk_txout* txout,
		     const uint8_t* buf,
		     size_t* byte_num)
{

    unsigned char* bufp = NULL;
    size_t len = 0;
    int arg_checked = 0;

    check(txout, "Failed to kyk_deseri_txout: txout is NULL");
    check(txout -> sc == NULL, "Failed to kyk_deseri_txout: txout -> sc is not NULL");
    check(buf, "Failed to kyk_deseri_txout: buf is NULL");
    arg_checked = 1;

    bufp = (unsigned char*)buf;
    beej_unpack(bufp, "<Q", &txout -> value);
    bufp += sizeof(txout -> value);

    len = kyk_unpack_varint(bufp, &txout -> sc_size);
    bufp += len;

    txout -> sc = calloc(txout -> sc_size, sizeof(*txout -> sc));
    check(txout -> sc, "Failed to kyk_deseri_txout: txout -> sc calloc failed");
    memcpy(txout -> sc, bufp, txout -> sc_size);
    bufp += txout -> sc_size;

    *byte_num = bufp - buf;
    
    return 0;

error:
    if(arg_checked){
	if(txout -> sc) {
	    free(txout -> sc);
	    txout -> sc = NULL;
	}
    }
    return -1;
}


int kyk_get_addr_from_txout(char** new_addr, const struct kyk_txout* txout)
{
    char* addr = NULL;    
    unsigned char* pbk_sc = NULL;
    int res = -1;
    
    check(new_addr, "Failed to kyk_get_addr_from_txout: addr is NULL");
    check(txout, "Failed to kyk_get_addr_from_txout: txout is NULL");
    check(txout -> sc_size > 0, "Failed to kyk_get_addr_from_txout: txout -> sc_size is invalid");
    check(txout -> sc, "Failed to kyk_get_addr_from_txout: txout -> sc is NULL");

    pbk_sc = txout -> sc;

    if(*pbk_sc == OP_DUP){
	/* pay-to-pubkey-hash */
	uint8_t pbkhash[20];
	check(*pbk_sc == OP_DUP, "Failed to kyk_get_addr_from_txout: invalid pbk_sc");
	pbk_sc++;
	check(*pbk_sc == OP_HASH160, "Failed to kyk_get_addr_from_txout: invalid pbk_sc");
	pbk_sc++;
	check(*pbk_sc == 0x14, "Failed to kyk_get_addr_from_txout: invalid pbk_sc");
	pbk_sc++;

	memcpy(pbkhash, pbk_sc, sizeof(pbkhash));

	res = kyk_address_from_pbkhash160(&addr, pbkhash, sizeof(pbkhash));
	check(res == 0, "Failed to kyk_get_addr_from_txout: kyk_address_from_pbkhash160 failed");

    } else if(*pbk_sc == 0x41){
	/* pay-to-pubkey uncompressed pubkey */
	uint8_t pubkey[65];
	pbk_sc++;
	memcpy(pubkey, pbk_sc, sizeof(pubkey));
	addr = kyk_make_address_from_pubkey(pubkey, sizeof(pubkey));
    } else if(*pbk_sc == 0x21){
	/* pay-to-pubkey compressed pubkey */
	uint8_t pubkey[33];
	pbk_sc++;
	memcpy(pubkey, pbk_sc, sizeof(pubkey));
	addr = kyk_make_address_from_pubkey(pubkey, sizeof(pubkey));
    } else {
	check(0, "Failed to kyk_get_addr_from_txout: invalid txout -> sc");
    }


    *new_addr = addr;

    return 0;
error:

    return -1;
}


int kyk_set_txin_script_sig(struct kyk_txin* txin,
			    uint8_t* der_buf,
			    size_t der_buf_len,
			    uint8_t* pubkey,
			    size_t publen,
			    uint32_t hashtype)
{
    uint8_t op_sep1 = 0;
    uint8_t op_sep2 = 0;
    uint8_t* sc_ptr = NULL;
    uint8_t sig_htype;

    check(txin, "Failed to kyk_set_txin_script_sig: txin is NULL");

    sig_htype = (uint8_t) hashtype;
    op_sep1 = der_buf_len + sizeof(sig_htype);
    op_sep2 = publen;

    txin -> sc_size = sizeof(op_sep1) + der_buf_len + sizeof(sig_htype) + sizeof(op_sep2) + publen;

    if(txin -> sc){
	free(txin -> sc);
	txin -> sc = NULL;
    }

    txin -> sc = calloc(txin -> sc_size, sizeof(*txin -> sc));
    check(txin -> sc, "Failed to kyk_set_txin_script_sig: txin -> sc failed");

    sc_ptr = txin -> sc;

    *sc_ptr = op_sep1;
    sc_ptr += 1;

    memcpy(sc_ptr, der_buf, der_buf_len);
    sc_ptr += der_buf_len;

    *sc_ptr = sig_htype;
    sc_ptr += 1;

    *sc_ptr = op_sep2;
    sc_ptr += 1;
    
    memcpy(sc_ptr, pubkey, publen);
    
    return 0;

error:

    return -1;
}

int kyk_copy_new_txout_from_utxo(struct kyk_txout** new_txout, const struct kyk_utxo* utxo)
{
    struct kyk_txout* txout = NULL;
    
    check(new_txout, "Failed to kyk_copy_new_txout_from_utxo: new_txout is NULL");
    check(utxo, "Failed to kyk_copy_new_txout_from_utxo: utxo is NULL");
    check(utxo -> sc_size > 0, "Failed to kyk_copy_new_txout_from_utxo: utxo -> sc_size is invalid");

    txout = calloc(1, sizeof(*txout));
    check(txout, "Failed to kyk_copy_new_txout_from_utxo: txout calloc failed");

    txout -> value = utxo -> value;
    txout -> sc_size = utxo -> sc_size;
    txout -> sc = calloc(txout -> sc_size, sizeof(*txout -> sc));

    memcpy(txout -> sc, utxo -> sc, txout -> sc_size);

    *new_txout = txout;

    return 0;
    
error:
    if(txout) kyk_free_txout(txout);
    return -1;
}

struct kyk_utxo* kyk_find_utxo_with_txin(const struct kyk_utxo_chain* utxo_chain,
					 const struct kyk_txin* txin)
{
    struct kyk_utxo* utxo = NULL;
    int txid_match = 0;
    int outidx_match = 0;

    utxo = utxo_chain -> hd;
    while(utxo){
	txid_match = kyk_digest_eq(utxo -> txid, txin -> pre_txid, sizeof(utxo -> txid));
	outidx_match = (txin -> pre_txout_inx == utxo -> outidx);
	if(txid_match && outidx_match){
	    return utxo;
	}

	utxo = utxo -> next;
    }

    return NULL;
}


int set_all_txins_sc_to_blank(struct kyk_tx* tx)
{
    struct kyk_txin* txin = NULL;
    varint_t i = 0;
    
    check(tx, "Failed to set_all_txins_sc_to_blank: tx is NULL");

    for(i = 0; i < tx -> vin_sz; i++){
	txin = tx -> txin + i;
	txin -> sc_size = 0;
	if(txin -> sc) free(txin -> sc);
	txin -> sc = NULL;
    }

    return 0;
    
error:

    return -1;
}


/* Txout with pay-to-pubkey-hash script */
int kyk_make_p2pkh_txout(struct kyk_txout* txout,
			   const char* addr,
			   size_t addr_len,
			   uint64_t value)
{
    unsigned char* sc = NULL;
    size_t sc_len = 0;
    int res = -1;
    
    check(txout, "Failed to kyk_make_p2pkh_txout: txout is NULL");
    check(addr, "Failed to kyk_make_p2pkh_txout: addr is NULL");
    check(addr_len > 0, "Failed to kyk_make_p2pkh_txout: addr_len is invalid");
    check(value > 0, "Failed to kyk_make_p2pkh_txout: value is invalid");

    res = kyk_build_p2pkh_sc_from_address(addr, addr_len, &sc, &sc_len);
    check(res == 0, "Failed to kyk_make_p2pkh_txout: kyk_build_p2pkh_sc_from_address failed");

    txout -> value = value;
    txout -> sc = sc;
    txout -> sc_size = sc_len;

    return 0;
    
error:
    if(sc) free(sc);
    return -1;
}

int kyk_unlock_utxo_chain(const struct kyk_utxo_chain* utxo_chain,
			  struct kyk_txin** new_txin_list,
			  varint_t* txin_count)
{
    const struct kyk_utxo* utxo = NULL;
    struct kyk_txin* txin_list = NULL;
    struct kyk_txin* txin = NULL;
    size_t i = 0;
    int res = -1;

    check(utxo_chain, "Failed to kyk_unlock_utxo_chain: utxo_chain is NULL");
    check(utxo_chain -> len > 0, "Failed to kyk_unlock_utxo_chain: utxo_chain -> len should be > 0");
    check(new_txin_list, "Failed to kyk_unlock_utxo_chain: new_txin_list is NULL");

    txin_list = calloc(utxo_chain -> len, sizeof(*txin_list));

    utxo = utxo_chain -> hd;
    while(utxo){
	txin = txin_list + i;
	res = kyk_unlock_utxo(utxo, txin);
	check(res == 0, "Failed to kyk_unlock_utxo_chain: kyk_unlock_utxo failed");
	utxo = utxo -> next;
	i++;
    }

    *new_txin_list = txin_list;
    *txin_count = utxo_chain -> len;

    return 0;
error:
    if(txin_list) {
	kyk_free_txin_list(txin_list, utxo_chain -> len);
    }
    return -1;
}

int kyk_unlock_utxo(const struct kyk_utxo* utxo,
		    struct kyk_txin* txin)
{
    check(utxo, "Failed to kyk_unlock_utxo: utxo is NULL");
    check(utxo -> value > 0, "Failed to kyk_unlock_utxo: utxo -> value is invalid");
    check(utxo -> sc_size > 0, "Failed to kyk_unlock_utxo: utxo -> sc_size is invalid");
    check(utxo -> spent == 0, "Failed to kyk_unlock_utxo: utxo has been spent");
    check(txin, "Failed to kyk_unlock_utxo: txin is NULL");

    memcpy(txin -> pre_txid, utxo -> txid, sizeof(txin -> pre_txid));
    txin -> pre_txout_inx = utxo -> outidx;
    txin -> sc_size = 0;
    if(txin -> sc) free(txin -> sc);
    txin -> sc = NULL;
    txin -> seq_no = NORMALLY_TX_SEQ_NO;

    return 0;
    
error:
    
    return -1;
}


void kyk_free_txin_list(struct kyk_txin* txin_list, varint_t len)
{
    varint_t i = 0;
    struct kyk_txin* txin = NULL;
    
    if(txin_list){
	for(i = 0; i < len; i++){
	    txin = txin_list + i;
	    if(txin -> sc){
		free(txin -> sc);
		txin -> sc = NULL;
	    }
	}

	free(txin_list);
    }
}

void kyk_free_txout_list(struct kyk_txout* txout_list, varint_t len)
{
    varint_t i = 0;
    struct kyk_txout* txout = NULL;

    if(txout_list){
	for(i = 0; i < len; i++){
	    txout = txout_list + i;
	    if(txout -> sc){
		free(txout -> sc);
		txout -> sc = NULL;
	    }
	}

	free(txout_list);
    }
}


int kyk_seri_tx_for_sig(const struct kyk_tx* tx,
			uint32_t htype,
			varint_t txin_index,
			const struct kyk_txout* txout,
			uint8_t** new_buf,
			size_t* buf_len)
{
    struct kyk_tx* tx_cpy = NULL;
    struct kyk_txin* txin = NULL;
    size_t tx_cpy_size = 0;
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    size_t buf_size = 0;
    int res = -1;

    check(tx, "Failed to kyk_seri_tx_for_sig: tx is NULL");
    check(txout, "Failed to kyk_seri_tx_for_sig: txout is NULL");
    check(new_buf, "Failed to kyk_seri_tx_for_sig: new_buf is NULL");
    
    res = kyk_copy_new_tx(&tx_cpy, tx);
    check(res == 0, "Failed to kyk_seri_tx_for_sig: kyk_copy_new_tx failed");

    /* make all txin to blank */
    set_all_txins_sc_to_blank(tx_cpy);

    /* set txin -> sc with txout's scriptPubkey */
    txin = tx_cpy -> txin + txin_index;
    res = placehold_txin_with_txout(txin, txout);
    check(res == 0, "Failed to kyk_seri_tx_for_sig: placehold_txin_with_txout failed");

    res = kyk_get_tx_size(tx_cpy, &tx_cpy_size);
    check(res == 0, "Failed to kyk_seri_tx_for_sig: kyk_get_tx_size failed");
    buf = calloc(tx_cpy_size + sizeof(htype), sizeof(*buf));
    check(buf, "Failed to kyk_seri_tx_for_sig: buf calloc failed");

    bufp = buf;

    buf_size = kyk_seri_tx(bufp, tx_cpy);
    check(buf_size == tx_cpy_size, "Failed to kyk_seri_tx_for_sig: kyk_seri_tx failed");
    bufp += buf_size;

    beej_pack(bufp, "<L", htype);

    *new_buf = buf;
    if(buf_len){
	*buf_len = buf_size + sizeof(htype);
    }
    
    return 0;
    
error:
    if(tx_cpy) kyk_free_tx(tx_cpy);
    if(buf) free(buf);
    return -1;
	
}

int placehold_txin_with_txout(struct kyk_txin* txin, const struct kyk_txout* txout)
{
    check(txin, "Failed to placehold_txin_with_txout: txin is NULL");
    check(txout, "Failed to placehold_txin_with_txout: txout is NULL");
    check(txout -> sc_size > 0, "Failed to placehold_txin_with_txout: txout -> sc_size is invalid");

    if(txin -> sc){
	free(txin -> sc);
	txin -> sc = NULL;
    }

    txin -> sc_size = txout -> sc_size;
    txin -> sc = calloc(txin -> sc_size, sizeof(*txin -> sc));
    check(txin -> sc, "Failed to placehold_txin_with_txout: txin -> sc calloc failed");

    memcpy(txin -> sc, txout -> sc, txin -> sc_size);

    return 0;

error:

    return -1;
}


int kyk_combine_txin_txout_for_script(uint8_t** sc_buf,
				      size_t* sc_buf_len,
				      const struct kyk_txin* txin,
				      const struct kyk_txout* txout)
{
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    size_t buf_len = 0;
    
    check(sc_buf, "Failed to kyk_combine_txin_txout_for_script: sc_buf is NULL");
    check(txin, "Failed to kyk_combine_txin_txout_for_script: txin is NULL");
    check(txin -> sc, "Failed to kyk_combine_txin_txout_for_script: txin -> sc is NULL");
    check(txout -> sc, "Failed to kyk_combine_txin_txout_for_script: txout -> sc is NULL");

    buf_len = txin -> sc_size + txout -> sc_size;
    buf = calloc(buf_len, sizeof(*buf));
    check(buf, "Failed to kyk_combine_txin_txout_for_script: buf calloc failed");

    bufp = buf;

    memcpy(bufp, txin -> sc, txin -> sc_size);
    bufp += txin -> sc_size;
    
    memcpy(bufp, txout -> sc, txout -> sc_size);

    if(sc_buf_len){
	*sc_buf_len = buf_len;
    }

    *sc_buf = buf;
    
    return 0;
    
error:
    if(buf) free(buf);
    return -1;
}


int kyk_get_total_txout_value(const struct kyk_tx* tx, uint64_t* value)
{
    const struct kyk_txout* txout = NULL;
    uint64_t total_value = 0;
    varint_t i = 0;
    
    check(tx, "Failed to kyk_get_total_txout_value: tx is NULL");

    for(i = 0; i < tx -> vout_sz; i++){
	txout = tx -> txout + i;
	total_value += txout -> value;
    }

    *value = total_value;
    
    return 0;

error:

    return -1;
}
