#ifndef KYK_BUFF_H__
#define KYK_BUFF_H__

#include <string.h>
#include <stdlib.h>

struct kyk_buff {
   uint8     *base;
   size_t     len;
   ssize_t    idx;
};

void free_kyk_buff(struct kyk_buff *buf)
{
    if(buf -> base) free(buf -> base);
    free(buf);
}

#endif
