#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "kyk_block.h"
#include "varint.h"
#include "beej_pack.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_buff.h"
#include "kyk_sha.h"
#include "kyk_utxo.h"
#include "dbg.h"


int kyk_free_utxo_chain(struct kyk_utxo_chain* utxo_chain)
{
    struct kyk_utxo* curr;
    
    if(utxo_chain){
	curr = utxo_chain -> hd;
	while(curr){
	    kyk_free_utxo(curr);
	    curr = curr -> next;
	}

	free(utxo_chain);
    }

    return 0;
    
}

int kyk_free_utxo(struct kyk_utxo* utxo)
{
    if(utxo){
	
	if(utxo -> btc_addr){
	    free(utxo -> btc_addr);
	    utxo -> btc_addr = NULL;
	}

	if(utxo -> sc){
	    free(utxo -> sc);
	    utxo -> sc = NULL;
	}
	
	free(utxo);
    }

    return 0;
}

int kyk_append_utxo_chain_from_block(struct kyk_utxo_chain* utxo_chain,
				     const struct kyk_block* blk)
{
    struct kyk_tx* tx = NULL;
    struct kyk_utxo_chain* tmp_chain = NULL;
    uint8_t blkhash[32];
    int res = -1;
    varint_t i = 0;

    check(utxo_chain, "Failed to kyk_append_utxo_chain_from_block: utxo_chain is NULL");
    check(blk, "Failed to kyk_append_utxo_chain_from_block: blk is NULL");
    check(blk -> hd, "Failed to kyk_append_utxo_chain_from_block: blk -> hd is NULL");
    check(blk -> tx_count > 0, "Failed to kyk_append_utxo_chain_from_block: blk -> tx_count is invalid");

    tmp_chain = calloc(1, sizeof(*tmp_chain));
    check(tmp_chain, "Failed to kyk_append_utxo_chain_from_block: tmp_chain calloc failed");
    kyk_init_utxo_chain(tmp_chain);

    res = kyk_blk_hash256(blkhash, blk -> hd);
    check(res == 0, "Failed to kyk_append_utxo_chain_from_block: kyk_blk_hash failed");

    for(i = 0; i < blk -> tx_count; i++){
	tx = blk -> tx + i;
	res = kyk_append_utxo_chain_from_tx(tmp_chain, blkhash, tx);
	check(res == 0, "Failed to kyk_append_utxo_chain_from_block: kyk_append_utxo_chain_from_tx failed");
    }

    res = kyk_combine_utxo_chain(utxo_chain, tmp_chain);
    check(res == 0, "Failed to kyk_append_utxo_chain_from_block: kyk_combine_utxo_chain failed");

    free(tmp_chain);
    
    return 0;
    
error:
    if(tmp_chain) kyk_free_utxo_chain(tmp_chain);
    return -1;
}

int kyk_append_utxo_chain_from_tx(struct kyk_utxo_chain* utxo_chain,
				  uint8_t* blkhash,
				  const struct kyk_tx* tx)
{
    uint8_t txid[32];
    struct kyk_utxo_chain* tmp_chain = NULL;
    struct kyk_txout* txout = NULL;
    struct kyk_utxo* utxo = NULL;
    int res = -1;
    varint_t i = 0;

    check(utxo_chain, "Failed to kyk_append_utxo_chain_from_tx: utxo_chain is NULL");
    check(blkhash, "Failed to kyk_append_utxo_chain_from_tx: blkhash is NULL");
    check(tx, "Failed to kyk_append_utxo_chain_from_tx: tx is NULL");
    check(tx -> vout_sz > 0, "Failed to kyk_append_utxo_chain_from_tx: tx -> vout_sz is invalid");

    tmp_chain = malloc(sizeof(*tmp_chain));
    check(tmp_chain, "Failed to kyk_append_utxo_chain_from_tx: tmp_chain malloc failed");
    kyk_init_utxo_chain(tmp_chain);

    res = kyk_tx_hash256(txid, tx);
    check(res == 0, "Failed to kyk_append_utxo_chain_from_tx: kyk_tx_hash256 failed");


    for(i = 0; i < tx -> vout_sz; i++){
	txout = tx -> txout + i;
	res = kyk_make_utxo(&utxo, txid, blkhash, txout, i);
	check(res == 0, "Failed to kyk_append_utxo_chain_from_tx: kyk_make_utxo failed");
	res = kyk_utxo_chain_append(tmp_chain, utxo);
	check(res == 0, "Failed to kyk_append_utxo_chain_from_tx: kyk_utxo_chain_append failed");
    }

    res = kyk_combine_utxo_chain(utxo_chain, tmp_chain);
    check(res == 0, "Failed to kyk_append_utxo_chain: kyk_combine_utxo_chain failed");

    free(tmp_chain);
    
    return 0;
error:
    if(tmp_chain){
	kyk_free_utxo_chain(tmp_chain);
    }
    return -1;
}

int kyk_combine_utxo_chain(struct kyk_utxo_chain* utxo_chain, const struct kyk_utxo_chain* tmp_chain)
{
    check(utxo_chain, "Failed to kyk_combine_utxo_chain: utxo_chain is NULL");
    check(tmp_chain, "Failed to kyk_combine_utxo_chain: tmp_chain is NULL");
    check(tmp_chain -> hd, "Failed to kyk_combine_utxo_chain: tmp_chain -> hd is NULL");
    check(tmp_chain -> tail, "Failed to kyk_combine_utxo_chain: tmp_chain -> tail is NULL");
    check(kyk_valid_utxo_chain(utxo_chain) == 0, "Failed to kyk_combine_utxo_chain: utxo_chain is invalid");
    check(kyk_valid_utxo_chain(tmp_chain) == 0, "Failed to kyk_combine_utxo_chain: tmp_chain is invalid");

    if(utxo_chain -> tail == NULL){
	utxo_chain -> hd = tmp_chain -> hd;
	utxo_chain -> tail = tmp_chain -> tail;	
    } else {
	utxo_chain -> tail -> next = tmp_chain -> hd;
	utxo_chain -> tail = tmp_chain -> tail;
    }

    utxo_chain -> len += tmp_chain -> len;
    
    return 0;

error:

    return -1;
}

int kyk_valid_utxo_chain(const struct kyk_utxo_chain* utxo_chain)
{
    check(utxo_chain,"Failed to kyk_valid_utxo_chain: utxo_chain is NULL");
    if(utxo_chain -> hd == NULL && utxo_chain -> tail){
	check(0, "Failed to kyk_valid_utxo_chain: utxo_chain is invalid");
    }

    if(utxo_chain -> hd && utxo_chain -> tail == NULL){
	check(0, "Failed to kyk_valid_utxo_chain: utxo_chain is invalid");
    }
	
    return 0;

error:
    return -1;
}

int kyk_make_utxo(struct kyk_utxo** new_utxo,
		  const uint8_t* txid,
		  const uint8_t* blkhash,
		  const struct kyk_txout* txout,
		  uint32_t txout_idx)
{
    struct kyk_utxo* utxo = NULL;
    char* btc_addr = NULL;
    int res = -1;

    check(new_utxo, "Failed to kyk_make_utxo: new_utxo is NULL");
    check(txid, "Failed to kyk_make_utxo: txid is NULL");
    check(blkhash, "Failed to kyk_make_utxo: blkhash is NULL");
    check(txout, "Failed to kyk_make_utxo: txout is NULL");

    utxo = calloc(1, sizeof(*utxo));
    check(utxo, "Failed to kyk_make_utxo: utxo calloc failed");
    
    memcpy(utxo -> txid, txid, sizeof(utxo -> txid));
    memcpy(utxo -> blkhash, blkhash, sizeof(utxo -> blkhash));

    res = kyk_get_addr_from_txout(&btc_addr, txout);
    check(res == 0, "Failed to kyk_make_utxo: kyk_get_addr_from_txout failed");

    utxo -> addr_len = strlen(btc_addr);
    utxo -> btc_addr = btc_addr;

    utxo -> outidx = txout_idx;

    utxo -> value = txout -> value;

    utxo -> sc_size = txout -> sc_size;
    utxo -> sc = calloc(utxo -> sc_size, sizeof(*utxo -> sc));
    check(utxo -> sc, "Failed to kyk_make_utxo: utxo -> sc calloc failed");
    memcpy(utxo -> sc, txout -> sc, utxo -> sc_size);

    utxo -> spent = 0;

    *new_utxo = utxo;

    return 0;

error:
    if(utxo) kyk_free_utxo(utxo);
    return -1;
}


int kyk_get_utxo_size(const struct kyk_utxo* utxo, size_t* utxo_size)
{
    size_t total = 0;
    check(utxo, "Failed to kyk_get_utxo_size: utxo is NULL");

    total += sizeof(utxo -> txid);
    total += sizeof(utxo -> blkhash);
    total += sizeof(utxo -> addr_len);
    total += utxo -> addr_len;
    total += sizeof(utxo -> outidx);
    total += sizeof(utxo -> value);
    total += get_varint_size(utxo -> sc_size);
    total += utxo -> sc_size;
    total += sizeof(utxo -> spent);

    *utxo_size = total;

    return 0;

error:

    return -1;
}


int kyk_get_utxo_chain_size(const struct kyk_utxo_chain* utxo_chain, size_t* len)
{
    const struct kyk_utxo* utxo_cpy = NULL;
    size_t utxo_len = 0;
    size_t total_len = 0;
    int res = -1;

    check(utxo_chain, "Failed to kyk_get_utxo_chain_size: utxo_chain is NULL");
    check(len, "Failed to kyk_get_utxo_chain_size: len is NULL");

    utxo_cpy = utxo_chain -> hd;
    
    while(utxo_cpy){
	res = kyk_get_utxo_size(utxo_cpy, &utxo_len);
	check(res == 0, "Failed to kyk_get_utxo_chain_size: kyk_get_utxo_size failed");
	total_len += utxo_len;
	utxo_cpy = utxo_cpy -> next;
    }

    *len = total_len;

    return 0;

error:

    return -1;
}


int kyk_seri_utxo_chain(uint8_t* buf,
			const struct kyk_utxo_chain* utxo_chain,
			size_t* check_num)
{
    struct kyk_utxo* utxo_cpy = NULL;
    uint8_t* bufp = NULL;
    size_t total_size = 0;
    size_t utxo_size = 0;
    int res = -1;

    check(buf, "Failed to kyk_seri_utxo_chain: buf is NULL");
    check(utxo_chain, "Failed to kyk_seri_utxo_chain: utxo_chain is NULL");

    bufp = buf;
    utxo_cpy = utxo_chain -> hd;

    while(utxo_cpy){
	res = kyk_seri_utxo(bufp, utxo_cpy, &utxo_size);
	check(res == 0, "Failed to kyk_seri_utxo_chain: kyk_seri_utxo failed");
	bufp += utxo_size;
	utxo_cpy = utxo_cpy -> next;
	total_size += utxo_size;
    }

    if(check_num){
	*check_num = total_size;
    }

    return 0;

error:
    if(buf) free(buf);
    return -1;
    
}

int kyk_seri_utxo(uint8_t* buf, const struct kyk_utxo* utxo, size_t* check_num)
{
    uint8_t* bufp = NULL;
    size_t len = 0;
    size_t total = 0;

    check(buf, "Failed to kyk_seri_utxo: buf is NULL");
    check(utxo, "Failed to kyk_seri_utxo: utxo is NULL");
    check(utxo -> addr_len > 0, "Failed to kyk_seri_utxo: utxo -> addr_len is invalid");
    check(utxo -> sc_size > 0, "Failed to kyk_seri_utxo: utxo -> sc_size is invalid");    

    bufp = buf;

    memcpy(bufp, utxo -> txid, sizeof(utxo -> txid));
    len = sizeof(utxo -> txid);
    total += len;
    bufp += len;
    
    memcpy(bufp, utxo -> blkhash, sizeof(utxo -> blkhash));
    len = sizeof(utxo -> blkhash);
    total += len;
    bufp += len;

    *bufp = utxo -> addr_len;
    len = sizeof(utxo -> addr_len);
    total += len;
    bufp += len;

    memcpy(bufp, utxo -> btc_addr, utxo -> addr_len);
    len = utxo -> addr_len;
    total += len;
    bufp += len;

    len = beej_pack(bufp, "<L", utxo -> outidx);
    total += len;
    bufp += len;

    len = beej_pack(bufp, "<Q", utxo -> value);
    total += len;
    bufp += len;

    len = kyk_pack_varint(bufp, utxo -> sc_size);
    total += len;
    bufp += len;

    memcpy(bufp, utxo -> sc, utxo -> sc_size);
    len = utxo -> sc_size;
    total += len;
    bufp += len;

    *bufp = utxo -> spent;
    len = sizeof(utxo -> spent);
    total += len;
    bufp += len;

    if(check_num){
	*check_num = total;
    }

    return 0;

error:

    return -1;
}

int kyk_deseri_utxo(struct kyk_utxo** new_utxo, const uint8_t* buf, size_t* check_num)
{
    struct kyk_utxo* utxo = NULL;
    const uint8_t* bufp = NULL;
    size_t len = 0;
    size_t total = 0;

    check(new_utxo, "Failed to kyk_deseri_utxo: utxo is NULL");
    check(buf, "Failed to kyk_deseri_utxo: buf is NULL");

    bufp = buf;
    utxo = calloc(1, sizeof(*utxo));
    check(utxo, "Failed to kyk_deseri_utxo: utxo calloc failed");

    memcpy(utxo -> txid, bufp, sizeof(utxo -> txid));
    len = sizeof(utxo -> txid);
    total += len;
    bufp += len;

    memcpy(utxo -> blkhash, bufp, sizeof(utxo -> blkhash));
    len = sizeof(utxo -> blkhash);
    total += len;
    bufp += len;

    utxo -> addr_len = *bufp;
    len = sizeof(utxo -> addr_len);
    total += len;
    bufp += len;

    check(utxo -> addr_len > 0, "Failed to kyk_deseri_utxo: utxo -> addr_len is invalid");
    utxo -> btc_addr = calloc(utxo -> addr_len + 1, sizeof(*utxo -> btc_addr));
    check(utxo -> btc_addr, "Failed to kyk_deseri_utxo: utxo -> btc_addr calloc failed");
    memcpy(utxo -> btc_addr, bufp, utxo -> addr_len);
    len = utxo -> addr_len;
    total += len;
    bufp += len;

    beej_unpack(bufp, "<L", &utxo -> outidx);
    len = sizeof(utxo -> outidx);
    total += len;
    bufp += len;

    beej_unpack(bufp, "<Q", &utxo -> value);
    len = sizeof(utxo -> value);
    total += len;
    bufp += len;

    len = kyk_unpack_varint(bufp, &utxo -> sc_size);
    check(utxo -> sc_size > 0, "Failed to kyk_deseri_utxo: utxo -> sc_size is invalid");
    total += len;
    bufp += len;

    utxo -> sc = calloc(utxo -> sc_size, sizeof(*utxo -> sc));
    check(utxo -> sc, "Failed to kyk_deseri_utxo: utxo -> sc calloc failed");
    memcpy(utxo -> sc, bufp, utxo -> sc_size);
    len = utxo -> sc_size;
    total += len;
    bufp += len;

    utxo -> spent = *bufp;
    len = sizeof(utxo -> spent);
    total += len;
    bufp += len;

    *new_utxo = utxo;

    if(check_num){
	*check_num = total;
    }

    return 0;

error:
    if(utxo) kyk_free_utxo(utxo);
    return -1;
}

int kyk_init_utxo_chain(struct kyk_utxo_chain* utxo_chain)
{
    check(utxo_chain, "Failed to kyk_init_utxo_chain: utxo_chain is NULL");

    utxo_chain -> hd = NULL;
    utxo_chain -> tail = NULL;
    utxo_chain -> curr = NULL;
    utxo_chain -> len = 0;

    return 0;
    
error:
    return -1;
}

int kyk_deseri_utxo_chain(struct kyk_utxo_chain* utxo_chain,
			  const uint8_t* buf,
			  size_t count,
			  size_t* check_num)
{
    struct kyk_utxo* utxo = NULL;
    const uint8_t* bufp = NULL;
    size_t len = 0;
    size_t total = 0;
    size_t i = 0;
    int res = -1;

    check(utxo_chain, "Failed to kyk_deseri_utxo_chain: new_utxo_chain is NULL");
    check(buf, "Failed to kyk_deseri_utxo_chain: buf is NULL");

    bufp = buf;

    for(i = 0; i < count; i++){
    	res = kyk_deseri_utxo(&utxo, bufp, &len);
    	check(res == 0, "Failed to kyk_deseri_utxo_chain: kyk_deseri_utxo failed");
    	check(utxo, "Failed to kyk_deseri_utxo_chain: utxo is NULL");
    	res = kyk_utxo_chain_append(utxo_chain, utxo);
    	check(res == 0, "Failed to kyk_deseri_utxo_chain: kyk_utxo_chain append failed");
    	bufp += len;
    	total += len;
    }

    if(check_num){
	*check_num = total;
    }
    
    return 0;
    
error:

    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    
    return -1;
}

int kyk_utxo_chain_append(struct kyk_utxo_chain* utxo_chain,
			  struct kyk_utxo* utxo)
{

    check(utxo_chain, "Failed to kyk_utxo_chain_append: utxo_chain is NULL");
    check(utxo, "Failed to kyk_utxo_chain_append: utxo is NULL");

    if(utxo_chain -> hd == NULL){
	utxo_chain -> hd = utxo;
	utxo_chain -> curr = utxo;
    }

    if(utxo_chain -> tail){
	check(utxo_chain -> tail -> next == NULL, "Failed to kyk_utxo_chain_append: invalid utxo_chain -> tail");
	utxo_chain -> tail -> next = utxo;
	utxo_chain -> tail = utxo_chain -> tail -> next;
    } else {
	utxo_chain -> tail = utxo;
    }

    utxo_chain -> len += 1;
    
    return 0;

error:

    return -1;
}


void kyk_print_utxo(const struct kyk_utxo* utxo)
{
    kyk_print_hex("txid", utxo -> txid, sizeof(utxo -> txid));
    kyk_print_hex("blkhash", utxo -> blkhash, sizeof(utxo -> blkhash));
    printf("addr_len:%d\n", utxo -> addr_len);
    printf("btc_addr:%s\n", utxo -> btc_addr);
    printf("outidx:  %d\n", utxo -> outidx);
    printf("value:   %llu\n", utxo -> value);
    printf("sc_size: %llu\n", utxo -> sc_size);
    kyk_print_hex("sc", utxo -> sc, utxo -> sc_size);
    printf("spent:   %d\n", utxo -> spent);
}

void kyk_print_utxo_chain(const struct kyk_utxo_chain* utxo_chain)
{
    struct kyk_utxo* utxo = NULL;
    size_t i = 0;

    utxo = utxo_chain -> hd;

    while(utxo){
	i += 1;
	printf("================================================================================UTXO#%zu\n", i);
	kyk_print_utxo(utxo);
	printf("================================================================================UTXO#%zu\n\n", i);
	utxo = utxo -> next;
    }
}

int kyk_utxo_match_addr(const struct kyk_utxo* utxo, const char* btc_addr)
{
    int res = -1;
    
    check(utxo, "Failed to kyk_utxo_match_addr: utxo is NULL");
    check(utxo -> addr_len > 0, "Failed to kyk_utxo_match_addr: utxo -> addr_len is invalid");
    check(utxo -> btc_addr, "Failed to kyk_utxo_match_addr: utxo -> btc_addr is NULL");
    check(btc_addr, "Failed to kyk_utxo_match_addr: btc_addr is NULL");

    res = strncmp(btc_addr, utxo -> btc_addr, utxo -> addr_len);

    return res;
    
error:

    return -1;
}

int kyk_copy_utxo(struct kyk_utxo** new_utxo, const struct kyk_utxo* src_utxo)
{
    struct kyk_utxo* utxo = NULL;
    
    check(new_utxo, "Failed to kyk_copy_utxo: new_utxo is NULL");
    check(src_utxo, "Failed to kyk_copy_utxo: src_utxo is NULL");

    utxo = calloc(1, sizeof(*utxo));
    check(utxo, "Failed to kyk_copy_utxo: utxo calloc failed");

    memcpy(utxo -> txid, src_utxo -> txid, sizeof(utxo -> txid));
    memcpy(utxo -> blkhash, src_utxo -> blkhash, sizeof(utxo -> blkhash));
    
    utxo -> addr_len = src_utxo -> addr_len;
    utxo -> btc_addr = calloc(utxo -> addr_len + 1, sizeof(*utxo -> btc_addr));
    check(utxo -> btc_addr, "Failed to kyk_copy_utxo: utxo -> btc_addr calloc failed");
    memcpy(utxo -> btc_addr, src_utxo -> btc_addr, utxo -> addr_len);

    utxo -> outidx = src_utxo -> outidx;
    utxo -> value = src_utxo -> value;
    
    utxo -> sc_size = src_utxo -> sc_size;
    utxo -> sc = calloc(utxo -> sc_size, sizeof(*utxo -> sc));
    check(utxo -> sc, "Failed to kyk_copy_utxo: utxo -> sc calloc failed");
    memcpy(utxo -> sc, src_utxo -> sc, utxo -> sc_size);

    utxo -> spent = src_utxo -> spent;

    utxo -> next = NULL;

    *new_utxo = utxo;

    return 0;

error:
    if(utxo) kyk_free_utxo(utxo);
    return -1;
}

int kyk_find_available_utxo_list(struct kyk_utxo_chain** new_utxo_chain,
				 const struct kyk_utxo_chain* src_utxo_chain,
				 uint64_t value)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_utxo* utxo = NULL;
    struct kyk_utxo* utxo_cpy = NULL;
    uint64_t total = 0;
    int res = -1;
    
    check(new_utxo_chain, "Failed to kyk_find_available_utxo_list: new_utxo_chain is NULL");
    check(src_utxo_chain, "Failed to kyk_find_available_utxo_list: src_utxo_chain is NULL");

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    check(utxo_chain, "Failed to kyk_find_available_utxo_list: utxo_chain calloc failed");

    kyk_init_utxo_chain(utxo_chain);

    utxo = src_utxo_chain -> hd;
    while(utxo){
	if(utxo -> value >= value){
	    res = kyk_copy_utxo(&utxo_cpy, utxo);
	    check(res == 0, "Failed to kyk_find_available_utxo_list: kyk_copy_utxo failed");
	    res = kyk_utxo_chain_append(utxo_chain, utxo_cpy);
	    check(res == 0, "Failed to kyk_find_available_utxo_list: kyk_utxo_chain_append failed");
	    break;
	}
	utxo = utxo -> next;
    }

    if(utxo_chain -> len == 0){
	utxo = src_utxo_chain -> hd;
	while(utxo){
	    res = kyk_copy_utxo(&utxo_cpy, utxo);
	    check(res == 0, "Failed to kyk_find_available_utxo_list: kyk_copy_utxo failed");
	    res = kyk_utxo_chain_append(utxo_chain, utxo_cpy);	    
	    check(res == 0, "Failed to kyk_find_available_utxo_list: kyk_utxo_chain_append failed");
	    kyk_utxo_chain_get_total_value(utxo_chain, &total);
	    if(total >= value){
		break;
	    }
	    utxo = utxo -> next;
	}
    }

    *new_utxo_chain = utxo_chain;
    
    return 0;
    
error:
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return -1;
}

int kyk_utxo_chain_get_total_value(const struct kyk_utxo_chain* utxo_chain, uint64_t* new_total)
{
    uint64_t total = 0;
    struct kyk_utxo* utxo = NULL;

    check(utxo_chain, "Failed to kyk_utxo_chain_get_total_value: utxo_chain is NULL");
    check(new_total, "Failed to kyk_utxo_chain_get_total_value: new_total is NULL");

    utxo = utxo_chain -> hd;
    while(utxo){
	total += utxo -> value;
	utxo = utxo -> next;
    }

    *new_total = total;
    
    return 0;

error:

    return -1;
}
