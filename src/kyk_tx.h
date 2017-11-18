#ifndef KYK_BITCOIN_KYK_TX_H
#define KYK_BITCOIN_KYK_TX_H

#define MAX_COINBASE_SC_LEN 100
#define MAX_SC_PUB_LEN 1000
#define KYK_COINBASE_SEQ_NO 0xFFFFFFFF
#define KYK_COINBASE_PRE_TX_INX 0xffffffff
#define KYK_COINBASE_PRE_TX_BYTE 0x00

#include "varint.h"

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

size_t kyk_seri_tx(unsigned char *buf, struct kyk_tx *tx);

struct kyk_txin *create_txin(const char *pre_txid,
			     uint32_t pre_tx_inx,
			     varint_t sc_size,
			     const char *sc,
			     uint32_t seq_no);

struct kyk_txout *create_txout(uint64_t value,
			       varint_t sc_size,
			       const char *sc);

void kyk_free_tx(struct kyk_tx *tx);

#endif
