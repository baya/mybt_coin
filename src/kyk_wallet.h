#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include <time.h>
#include "kyk_defs.h"
#include "kyk_ldb.h"

struct kyk_wallet_key {
    struct key  *key;
    time_t       birth;
    char        *desc;
    char        *btc_addr;
    uint8_t     *pub;
    size_t       pubLen;
    uint160      pub_key;
    uint32_t     cfg_idx;
    bool         spendable;
};

struct kyk_wallet {
    char *wdir;
    char *blk_dir;
    char *idx_db_path;
    struct kyk_block_db* blk_index_db;
};

struct kyk_wallet* kyk_init_wallet(const char *wdir);
struct kyk_wallet* kyk_open_wallet(const char *wdir);
struct kyk_bkey_val* w_get_bval(const struct kyk_wallet* wallet,
				 const char* blk_hash_str,
				 char **errptr);
void kyk_destroy_wallet(struct kyk_wallet* wallet);

int kyk_wallet_add_key(struct kyk_wallet* wallet,
		       const char*    desc,
		       char**         btc_addr);


#endif
