#ifndef __BLOCK_STORE_H__
#define __BLOCK_STORE_H__

#include "kyk_ldb.h"

void kyk_store_block(struct kyk_block_db* blk_db,
		     struct kyk_bkey_val* bval,
		     char **errptr
    );

struct kyk_bkey_val* kyk_read_block(struct kyk_block_db* blk_db,
				    const char* blk_hash,
				    char** errptr
    );

#endif
