#ifndef KYK_BITCOIN_KYK_TX_H
#define KYK_BITCOIN_KYK_TX_H

#include "varint.h"

#define NORMALLY_TX_SEQ_NO 0xFFFFFFFF
#define MORMALLY_TX_LOCK_TIME 0
#define COINBASE_PRE_TXID "0000000000000000000000000000000000000000000000000000000000000000"
#define COINBASE_INX 0xffffffff

/* 1 BTC = 10 ** 8 Satoshi */
#define ONE_BTC_COIN_VALUE 100000000

/* Total BTC Value */

#define TOTAL_BTC_VALUE 2000 * 10000 * ONE_BTC_COIN_VALUE

struct kyk_bon_buff;

struct kyk_utxo;
struct kyk_utxo_chain;

/* https://bitcoin.org/en/developer-reference#raw-transaction-format */
struct kyk_tx {
    uint32_t version;
    varint_t vin_sz;          /* In-counter */
    struct kyk_txin *txin;
    varint_t vout_sz;         /* Out-counter */
    struct kyk_txout *txout;
    uint32_t lock_time;
};

struct kyk_txin{
    unsigned char pre_txid[32];
    uint32_t pre_txout_inx;        /* previous Txout Index */
    varint_t sc_size;
    unsigned char *sc;
    uint32_t seq_no;
};

struct kyk_txout{
    uint64_t value;
    varint_t sc_size;
    unsigned char *sc;
};


void kyk_print_txout(const struct kyk_txout* txout);

int kyk_tx_hash256(uint8_t* digest, const struct kyk_tx* tx);

int kyk_seri_tx_list(struct kyk_bon_buff* buf_list,
		     const struct kyk_tx* tx_list,
		     size_t tx_count);

size_t kyk_seri_tx(unsigned char *buf, const struct kyk_tx *tx);

struct kyk_txin *create_txin(const char *pre_txid,
			     uint32_t pre_txout_inx,
			     varint_t sc_size,
			     const char *sc,
			     uint32_t seq_no);

struct kyk_txout *create_txout(uint64_t value,
			       varint_t sc_size,
			       const char *sc);

void kyk_free_tx(struct kyk_tx *tx);
void kyk_free_txin(struct kyk_txin *txin);
void kyk_free_txout(struct kyk_txout *txout);

int kyk_make_coinbase_tx(struct kyk_tx** cb_tx,
			 const char* note,
			 uint64_t outValue,
			 const uint8_t* pub,
			 size_t pub_len);


struct kyk_tx* kyk_create_tx(uint32_t version,
			     varint_t vin_sz,
			     varint_t vout_sz,
			     uint32_t lock_time);

int kyk_get_tx_size(const struct kyk_tx* tx, size_t* tx_size);

int kyk_add_txin(struct kyk_tx* tx,
		 size_t inx,
		 const struct kyk_txin* out_txin);

int kyk_add_txout(struct kyk_tx* tx,
		  size_t inx,
		  const struct kyk_txout* out_txout);

int kyk_copy_tx(struct kyk_tx* dest_tx, const struct kyk_tx* src_tx);

int kyk_copy_txout(struct kyk_txout* txout, const struct kyk_txout* src_txout);


int kyk_deseri_tx(struct kyk_tx* tx,
		  const uint8_t* buf,
		  size_t* byte_num);

int kyk_deseri_tx_list(struct kyk_tx* tx_list,
		       size_t tx_count,
		       const uint8_t* buf,
		       size_t* byte_num);



int kyk_get_addr_from_txout(char** new_addr, const struct kyk_txout* txout);


void kyk_free_txin_list(struct kyk_txin* txin_list, varint_t tx_count);

int kyk_unlock_utxo(const struct kyk_utxo* utxo,
		    struct kyk_txin* txin);

int kyk_unlock_utxo_chain(const struct kyk_utxo_chain* utxo_chain,
			  struct kyk_txin** new_txin_list,
			  varint_t* txin_count);


int kyk_make_tx_from_utxo_chain(struct kyk_tx** new_tx,
				uint64_t amount,         /* amount excluded miner fee        */
				uint64_t mfee,           /* miner fee                        */
				const char* to_addr,     /* send btc amount to this address  */
				const char* mc_addr,     /* make change back to this address */
				uint32_t version,
				const struct kyk_utxo_chain* utxo_chain);

int kyk_make_p2pkh_txout(struct kyk_txout* txout,
			 const char* addr,
			 size_t addr_len,
			 uint64_t value);

void kyk_free_txout_list(struct kyk_txout* txout_list, varint_t len);

int kyk_deseri_new_tx(struct kyk_tx** new_tx,
		      const uint8_t* buf,
		      size_t* byte_num);

int kyk_copy_new_tx(struct kyk_tx** new_tx, const struct kyk_tx* src_tx);

int kyk_seri_tx_to_new_buf(const struct kyk_tx* tx,
			   uint8_t** new_buf,
			   size_t* buf_len);


int kyk_seri_tx_for_sig(const struct kyk_tx* tx,
			varint_t txin_index,
			const struct kyk_txout* txout,
			uint8_t** new_buf,
			size_t* buf_len);


int kyk_combine_txin_txout_for_script(uint8_t** sc_buf,
				      size_t* sc_buf_len,
				      const struct kyk_txin* txin,
				      const struct kyk_txout* txout);


int kyk_copy_txin(struct kyk_txin* txin, const struct kyk_txin* src_txin);

struct kyk_utxo* kyk_find_utxo_with_txin(const struct kyk_utxo_chain* utxo_chain,
					 const struct kyk_txin* txin);

int kyk_copy_new_txout_from_utxo(struct kyk_txout** new_txout, const struct kyk_utxo* utxo);

#endif
