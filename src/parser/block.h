#ifndef KYK_BLOCK_PARSER_H__
#define KYK_BLOCK_PARSER_H__

#include "kyk_block.h"
#include "kyk_tx.h"

int kyk_parse_block(struct kyk_block* blk, const uint8_t* buf, size_t buf_len);

#endif
