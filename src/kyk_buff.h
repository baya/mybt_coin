#ifndef KYK_BUFF_H__
#define KYK_BUFF_H__

#include <string.h>
#include <stdlib.h>

struct kyk_buff {
    uint8_t   *base;
    size_t    len;
    size_t    base_len;
    size_t    idx;
};

void free_kyk_buff(struct kyk_buff *buf);
struct kyk_buff* create_kyk_buff(size_t blen);

#endif
