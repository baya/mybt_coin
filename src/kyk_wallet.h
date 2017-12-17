#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include <time.h>
#include "kyk_defs.h"
#include "kyk_ldb.h"

struct kyk_blk_hd_chain;

struct kyk_utxo_chain;

struct kyk_wallet_key {
    struct kyk_key* key;
    char        *priv_str;
    char        *desc;
    char        *btc_addr;
    uint8_t     *pub_key;
    size_t       pub_len;
    uint32_t     cfg_idx;
};


struct kyk_wallet {
    char* wdir;
    char* blk_dir;
    char* idx_db_path;
    char* wallet_cfg_path;
    char* blk_hd_chain_path;
    char* utxo_path;
    struct kyk_block_db* blk_index_db;
    struct config* wallet_cfg;
};

int kyk_setup_wallet(struct kyk_wallet** outWallet, const char* wdir);

struct kyk_wallet* kyk_open_wallet(const char *wdir);

int kyk_init_wallet(struct kyk_wallet* wallet);

struct kyk_bkey_val* w_get_bval(const struct kyk_wallet* wallet,
				 const char* blk_hash_str,
				 char **errptr);
void kyk_destroy_wallet(struct kyk_wallet* wallet);

struct kyk_wallet_key* kyk_create_wallet_key(uint32_t cfg_idx,
					     const char* desc);

int kyk_wallet_add_key(struct kyk_wallet* wallet,
		       struct kyk_wallet_key* k);

int kyk_wallet_check_config(struct kyk_wallet* wallet, const char* wdir);

void kyk_destroy_wallet_key(struct kyk_wallet_key* k);

int kyk_wallet_add_address(struct kyk_wallet* wallet, const char* desc);

int kyk_save_blk_header_chain(const struct kyk_wallet* wallet,
			      const struct kyk_blk_hd_chain* hd_chain);

int kyk_load_blk_header_chain(struct kyk_blk_hd_chain** hd_chain,
			      const struct kyk_wallet* wallet);

struct kyk_wallet* kyk_new_wallet(const char *wdir);

int kyk_wallet_get_pubkey(uint8_t** pubkey,
			  size_t* pbk_len,
			  const struct kyk_wallet* wallet,
			  const char* name);


int kyk_wallet_save_block(const struct kyk_wallet* wallet, const struct kyk_block* blk);

int kyk_load_utxo_chain(struct kyk_utxo_chain** new_utxo_chain,
			const struct kyk_wallet* wallet);

int kyk_wallet_save_utxo_chain(const struct kyk_wallet* wallet,
			       const struct kyk_utxo_chain* utxo_chain);

int kyk_load_utxo_chain_from_chainfile_buf(struct kyk_utxo_chain* utxo_chain,
					   const uint8_t* buf,
					   size_t buf_len);

int kyk_wallet_query_value_by_addr(const char* btc_addr,
				   const struct kyk_utxo_chain* utxo_chain,
				   uint64_t* value);

int kyk_wallet_load_addr_list(const struct kyk_wallet* wallet,
			      char** new_addr_list[],
			      size_t* nlen);

int kyk_wallet_query_total_balance(const struct kyk_wallet* wallet, uint64_t* balance);

int kyk_wallet_make_tx(struct kyk_tx** new_tx,
		       const struct kyk_wallet* wallet,
		       uint64_t value,
		       const char* btc_addr);

#endif
