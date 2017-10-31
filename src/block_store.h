#ifndef __BLOCK_STORE_H__
#define __BLOCK_STORE_H__

#include "kyk_block.h"
#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_ser.h"
#include "kyk_ldb.h"
#include "kyk_buff.h"

void kyk_store_block(struct kyk_block_db* blk_db,
		     struct kyk_bkey_val* bval,
		     char **errptr
    );
#endif
