#ifndef KYK_BITCOIN_KYK_TX_H
#define KYK_BITCOIN_KYK_TX_H

#include "varint.h"

#define NORMALLY_TX_SEQ_NO 0xFFFFFFFF
#define COINBASE_PRE_TXID "0000000000000000000000000000000000000000000000000000000000000000"
#define COINBASE_INX 0xffffffff

struct kyk_bon_buff;

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
    uint32_t pre_tx_inx;
    varint_t sc_size;
    unsigned char *sc;
    uint32_t seq_no;
};

struct kyk_txout{
    uint64_t value;
    varint_t sc_size;
    unsigned char *sc;
};

int kyk_tx_hash256(uint8_t* digest, const struct kyk_tx* tx);

int kyk_seri_tx_list(struct kyk_bon_buff* buf_list,
		     const struct kyk_tx* tx_list,
		     size_t tx_count);

size_t kyk_seri_tx(unsigned char *buf, const struct kyk_tx *tx);

struct kyk_txin *create_txin(const char *pre_txid,
			     uint32_t pre_tx_inx,
			     varint_t sc_size,
			     const char *sc,
			     uint32_t seq_no);

struct kyk_txout *create_txout(uint64_t value,
			       varint_t sc_size,
			       const char *sc);

void kyk_free_tx(struct kyk_tx *tx);
void kyk_free_txin(struct kyk_txin *txin);
void kyk_free_txout(struct kyk_txout *txout);

int kyk_make_coinbase_tx(struct kyk_tx* tx,
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


int kyk_deseri_tx(struct kyk_tx* tx,
		  const uint8_t* buf,
		  size_t* byte_num);

int kyk_deseri_tx_list(struct kyk_tx* tx_list,
		       size_t tx_count,
		       const uint8_t* buf,
		       size_t* byte_num);


#endif
