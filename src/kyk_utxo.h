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
    struct kyk_utxo* refer_to;
};


struct kyk_utxo_chain {
    struct kyk_utxo* hd;
    struct kyk_utxo* tail;
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

int kyk_deseri_utxo_chain(struct kyk_utxo_chain* utxo_chain,
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

void kyk_print_utxo(const struct kyk_utxo* utxo);

int kyk_utxo_match_addr(const struct kyk_utxo* utxo, const char* btc_addr);

int kyk_find_available_utxo_list(struct kyk_utxo_chain** new_utxo_chain,
				 const struct kyk_utxo_chain* src_utxo_chain,
				 uint64_t value);


int kyk_utxo_chain_get_total_value(const struct kyk_utxo_chain* utxo_chain, uint64_t* new_total);

void kyk_print_utxo_chain(const struct kyk_utxo_chain* utxo_chain);

int kyk_copy_utxo(struct kyk_utxo** new_utxo, const struct kyk_utxo* src_utxo);

int kyk_refer_to_utxo(struct kyk_utxo* utxo, struct kyk_utxo* ref_utxo);

int kyk_remove_spent_utxo(struct kyk_utxo_chain** new_utxo_chain,
			  const struct kyk_utxo_chain* src_utxo_chain);

int kyk_utxo_chain_append_force(struct kyk_utxo_chain* utxo_chain,
				struct kyk_utxo* utxo);

int kyk_get_total_utxo_value(const struct kyk_utxo_chain* utxo_chain, uint64_t* value);

#endif
