#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_buff.h"
#include "dbg.h"

void free_kyk_buff(struct kyk_buff *buf)
{
    if(buf){
	if(buf -> base) {
	    free(buf -> base);
	    buf -> base = NULL;
	}
	free(buf);
    }
}

struct kyk_buff* create_kyk_buff(size_t blen)
{
    struct kyk_buff* buf = malloc(sizeof(struct kyk_buff));
    check(buf != NULL, "failed to malloc buff");
    
    buf -> base = malloc(blen * sizeof(uint8_t));
    check(buf -> base != NULL, "failed to malloc buff base");

    buf -> len = 0;
    buf -> base_len = blen;
    buf -> idx = 0;

    return buf;

error:
    return NULL;
    
}

void free_kyk_bon_buff(struct kyk_bon_buff* buf)
{
    if(buf){
	if(buf -> base) {
	    free(buf -> base);
	    buf -> base = NULL;
	}
	free(buf);
    }
}
