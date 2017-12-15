#ifndef KYK_UTXO_H__
#define KYK_UTXO_H__


struct kyk_utxo{
    uint8_t  txid[32];    /* Tx hash    */
    uint8_t  blkhash[32]; /* Block Hash */
    uint8_t  addr_len;
    char*    btc_addr;
    uint32_t outidx;      /* Txout Index */
    uint64_t value;       /* Txout value */
    varint_t sc_size;
    unsigned char* sc;    /* Txout Pubkey script */
    uint8_t  spent;
    struct kyk_utxo* next;
};


struct kyk_utxo_chain {
    struct kyk_utxo* hd;
    struct kyk_utxo* tail;
    struct kyk_utxo* curr;
    uint32_t len;
};


int kyk_free_utxo_chain(struct kyk_utxo_chain* utxo_chain);
int kyk_free_utxo(struct kyk_utxo* utxo);

int kyk_deseri_utxo(struct kyk_utxo** new_utxo,
		    const uint8_t* buf,
		    size_t* check_num);

int kyk_seri_utxo(uint8_t* buf,
		  const struct kyk_utxo* utxo,
		  size_t* check_num);

int kyk_init_utxo_chain(struct kyk_utxo_chain* utxo_chain);

int kyk_deseri_utxo_chain(struct kyk_utxo_chain** new_utxo_chain,
			  const uint8_t* buf,
			  size_t count,
			  size_t* check_num);

int kyk_utxo_chain_append(struct kyk_utxo_chain* utxo_chain,
			  struct kyk_utxo* utxo);

int kyk_get_utxo_size(const struct kyk_utxo* utxo, size_t* utxo_size);

int kyk_make_utxo(struct kyk_utxo** new_utxo,
		  const uint8_t* txid,
		  const uint8_t* blkhash,
		  const struct kyk_txout* txout,
		  uint32_t txout_idx);

int kyk_valid_utxo_chain(const struct kyk_utxo_chain* utxo_chain);

int kyk_combine_utxo_chain(struct kyk_utxo_chain* utxo_chain,
			   const struct kyk_utxo_chain* tmp_chain);

int kyk_append_utxo_chain_from_tx(struct kyk_utxo_chain* utxo_chain,
				  uint8_t* blkhash,
				  const struct kyk_tx* tx);

int kyk_append_utxo_chain_from_block(struct kyk_utxo_chain* utxo_chain,
				     const struct kyk_block* blk);

int kyk_get_utxo_chain_size(const struct kyk_utxo_chain* utxo_chain, size_t* len);

int kyk_seri_utxo_chain(uint8_t* buf,
			const struct kyk_utxo_chain* utxo_chain,
			size_t* check_num);


#endif
