#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include <time.h>
#include "kyk_defs.h"
#include "kyk_ldb.h"

struct kyk_blk_hd_chain;

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


#endif
