#ifndef KYK_WALLET_H__
#define KYK_WALLET_H__

#include "kyk_ldb.h"

struct kyk_wallet;

struct kyk_wallet* kyk_init_wallet(char *wdir);
void kyk_destroy_wallet(struct kyk_wallet* wallet);

#endif
