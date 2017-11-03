#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include "kyk_ldb.h"

struct kyk_wallet;

struct kyk_wallet* kyk_init_wallet(const char *wdir);
struct kyk_wallet* kyk_open_wallet(const char *wdir);
struct kyk_bkey_val* w_get_bval(const struct kyk_wallet* wallet,
				 const char* blk_hash_str,
				 char **errptr);
void kyk_destroy_wallet(struct kyk_wallet* wallet);

#endif
