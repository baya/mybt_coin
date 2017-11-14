#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include <time.h>
#include "kyk_defs.h"
#include "kyk_ldb.h"

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
    char *wdir;
    char *blk_dir;
    char *idx_db_path;
    char *wallet_cfg_path;
    struct kyk_block_db* blk_index_db;
    struct config* wallet_cfg;
};

struct kyk_wallet* kyk_init_wallet(const char *wdir);
struct kyk_wallet* kyk_open_wallet(const char *wdir);
struct kyk_bkey_val* w_get_bval(const struct kyk_wallet* wallet,
				 const char* blk_hash_str,
				 char **errptr);
void kyk_destroy_wallet(struct kyk_wallet* wallet);

struct kyk_wallet_key* kyk_create_wallet_key(uint32_t cfg_idx,
					     const char* desc
    );


int kyk_wallet_add_key(struct kyk_wallet* wallet,
		       struct kyk_wallet_key* k);

int kyk_wallet_check_config(struct kyk_wallet* wallet, const char* wdir);

#endif
