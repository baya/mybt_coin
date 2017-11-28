#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_block.h"
#include "kyk_buff.h"
#include "parser/block.h"
#include "dbg.h"

int kyk_parse_block(struct kyk_block* blk, const uint8_t* buf, size_t buf_len)
{
    uint8_t* bufp = NULL;
    int res = -1;
    size_t len = 0;

    check(blk, "Failed to kyk_parse_block: blk is NULL");
    /* we need a clean block with blank block header */
    check(blk -> hd == NULL, "Failed to kyk_parse_block: blk -> hd is not NULL");
    /* we need a clean block with blank tx list */
    check(blk -> tx == NULL, "Failed to kyk_parse_block: blk -> tx is not NULL");
    check(buf, "Failed to kyk_parse_block: buf is NULL");

    bufp = buf;

    blk -> hd = calloc(1, sizeof(*blk -> hd));
    check(blk -> hd, "Failed to kyk_parse_block: blk -> hd calloc failed");

    res = kyk_deseri_blk_header(blk -> hd, buf, &len);
    check(res == 0, "Failed to kyk_parse_block: kyk_deseri_blk_header failed");
    bufp += len;

    
    return 0;

error:

    return -1;
}

