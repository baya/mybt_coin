#ifndef __GENS_BLOCK_H__

#define __GENS_BLOCK_H__

#include "kyk_block.h"
#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_script.h"
#include "kyk_address.h"
#include "kyk_mkl_tree.h"
#include "kyk_ser.h"
#include "kyk_difficulty.h"
#include "kyk_hash_nonce.h"
#include "kyk_pem.h"

/* if you set another new gens block, you need change this to yours */
#define KYK_GENS_BLK_HASH_HEX "0000876c9ef8c1f8b2a3012ec1bdea7296f95ae21681799f8adf967f548bf8f3"

struct kyk_block* make_gens_block();

#endif
