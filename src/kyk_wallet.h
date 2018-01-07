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

struct kyk_wkey {
    char*    addr;
    uint8_t* priv;
    size_t   priv_len;
    uint8_t* pub;
    size_t   pub_len;
    struct kyk_wkey* next;
};

struct kyk_wkey_chain {
    struct kyk_wkey* hd;
    struct kyk_wkey* tail;
    size_t len;
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

int kyk_setup_spv_wallet(struct kyk_wallet** new_wallet, const char* wdir);

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
			      const struct kyk_blk_hd_chain* hd_chain,
			      const char* mode);

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
		       struct kyk_utxo_chain** new_utxo_chain,
		       uint32_t version,
		       struct kyk_wallet* wallet,		       
		       struct kyk_utxo_chain* wallet_utxo_chain,
		       uint64_t value,
		       const char* btc_addr);

int kyk_wallet_load_key_list(struct kyk_wallet* wallet, struct kyk_wkey_chain** new_wkey_chain);

void kyk_wkey_chain_free(struct kyk_wkey_chain* wkey_chain);

void kyk_print_wkey_chain(const struct kyk_wkey_chain* wkey_chain);

void kyk_print_wkey(const struct kyk_wkey* wkey);

void kyk_wkey_free(struct kyk_wkey* wkey);

int kyk_wkey_chain_append_wkey(struct kyk_wkey_chain* wkey_chain,
			       struct kyk_wkey* wkey);


int kyk_wallet_make_tx_from_utxo_chain(struct kyk_tx** new_tx,
				       uint64_t amount,         /* amount excluded miner fee        */
				       uint64_t mfee,           /* miner fee                        */
				       const char* to_addr,     /* send btc amount to this address  */
				       const char* mc_addr,     /* make change back to this address */
				       uint32_t version,
				       const struct kyk_utxo_chain* utxo_chain,
				       const struct kyk_wkey_chain* wkey_chain);


int kyk_wallet_do_sign_tx(const struct kyk_tx* tx,
			  const struct kyk_utxo_chain* utxo_chain,
			  const struct kyk_wkey_chain* wkey_chain);


struct kyk_wkey* kyk_find_wkey_by_addr(const struct kyk_wkey_chain* wkey_chain, const char* addr);

int kyk_wallet_make_coinbase_block(struct kyk_block** new_blk, const struct kyk_wallet* wallet);

int kyk_wallet_cmd_make_tx(struct kyk_block** new_blk,
			   struct kyk_wallet* wallet,
			   long double btc_num,
			   const char* btc_addr);

int kyk_wallet_set_utxo_chain_spent(struct kyk_utxo_chain* utxo_chain);

int kyk_wallet_get_mfee(const struct kyk_tx* tx,
			const struct kyk_utxo_chain* utxo_chain,
			uint64_t* mfee);

int kyk_wallet_query_block(const struct kyk_wallet* wallet,
			   const char* blk_hash,
			   struct kyk_block** new_blk);

int kyk_wallet_get_new_block_from_bval(const struct kyk_wallet* wallet,
				       const struct kyk_bkey_val* bval,
				       struct kyk_block** new_blk);


int kyk_wallet_query_block_by_hashbytes(const struct kyk_wallet* wallet,
					const uint8_t* blk_hash,
					struct kyk_block** new_blk);

#endif
