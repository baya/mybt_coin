#ifndef __KYK_ADDRESS_H__
#define __KYK_ADDRESS_H__

#include "kyk_defs.h"
#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "kyk_base58.h"


char *kyk_make_address(const uint8_t *priv_bytes, size_t priv_len);
char *kyk_make_address_from_pubkey(uint8_t *pub, size_t pub_len);
int kyk_address_from_pbkhash160(char** new_addr, const uint8_t* pbkhash, size_t len);

#endif
