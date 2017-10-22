#ifndef __KYK_ADDRESS_H__
#define __KYK_ADDRESS_H__

#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "kyk_base58.h"


char *kyk_make_address(const uint8_t *prive_bytes);

#endif
