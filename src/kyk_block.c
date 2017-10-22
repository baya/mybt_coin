#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_block.h"
#include "beej_pack.h"
#include "kyk_utils.h"


size_t kyk_seri_blk_hd(uint8_t *buf, const struct kyk_blk_header *hd)
{
    size_t len = 0;
    size_t total = 0;

    len = beej_pack(buf, "<L", hd -> version);
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> tts);
    buf += len;
    total += len;
    
    len = beej_pack(buf, "<L", hd -> bts);
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> nonce);
    buf += len;
    total += len;

    return total;
}

size_t kyk_seri_blk_hd_without_nonce(uint8_t *buf, const struct kyk_blk_header *hd)
{
    size_t len = 0;
    size_t total = 0;

    len = beej_pack(buf, "<L", hd -> version);
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> pre_blk_hash, sizeof(hd -> pre_blk_hash));
    buf += len;
    total += len;

    len = kyk_reverse_pack_chars(buf, (unsigned char *)hd -> mrk_root_hash, sizeof(hd -> mrk_root_hash));
    buf += len;
    total += len;

    len = beej_pack(buf, "<L", hd -> tts);
    buf += len;
    total += len;
    
    len = beej_pack(buf, "<L", hd -> bts);
    buf += len;
    total += len;

    return total;
}

