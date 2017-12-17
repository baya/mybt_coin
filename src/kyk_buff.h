#ifndef KYK_BUFF_H__
#define KYK_BUFF_H__

#include "kyk_defs.h"

struct kyk_buff {
    uint8_t   *base;
    size_t    len;
    size_t    base_len;
    size_t    idx;
};

struct kyk_bon_buff {
    uint8_t *base;
    size_t len;
};

void free_kyk_buff(struct kyk_buff *buf);
struct kyk_buff* create_kyk_buff(size_t blen);
void free_kyk_bon_buff(struct kyk_bon_buff* buf);

#endif
