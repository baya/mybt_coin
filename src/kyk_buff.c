#include "kyk_buff.h"

void free_kyk_buff(struct kyk_buff *buf)
{
    if(buf -> base) free(buf -> base);
    free(buf);
}

