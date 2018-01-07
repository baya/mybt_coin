#include <stdlib.h>
#include "varint.h"
#include "dbg.h"

size_t kyk_pack_varint(unsigned char *buf, varint_t v)
{
    unsigned char *p = buf;

    if (v < 0xfd) {
	(*p++) = v;
    } else if (v <= 0xffff) {
	(*p++) = 0xfd;
	(*p++) = v;
	(*p++) = v >> 8;
    } else if (v <= 0xffffffff) {
	(*p++) = 0xfe;
	(*p++) = v;
	(*p++) = v >> 8;
	(*p++) = v >> 16;
	(*p++) = v >> 24;
    } else {
	(*p++) = 0xff;
	(*p++) = v;
	(*p++) = v >> 8;
	(*p++) = v >> 16;
	(*p++) = v >> 24;
	(*p++) = v >> 32;
	(*p++) = v >> 40;
	(*p++) = v >> 48;
	(*p++) = v >> 56;
    }
    return p - buf;
}

size_t kyk_unpack_varint(const unsigned char *buf, varint_t *val)
{
    switch (*buf) {
    case 0xfd:
	*val = ((uint64_t)buf[2] << 8) | buf[1];
	
	return 3;
    case 0xfe:
	*val = ((uint64_t)buf[4] << 24) |
	    ((uint64_t)buf[3] << 16) |
	    ((uint64_t)buf[2] << 8) |
	    buf[1];
	
	return 5;
    case 0xff:
	*val = ((uint64_t)buf[8] << 56) |
	    ((uint64_t)buf[7] << 48) |
	    ((uint64_t)buf[6] << 40) |
	    ((uint64_t)buf[5] << 32) |
	    ((uint64_t)buf[4] << 24) |
	    ((uint64_t)buf[3] << 16) |
	    ((uint64_t)buf[2] << 8)  |
	    buf[1];
	
	return 9;
    default:
	*val = *buf;
	return 1;
    }
}

size_t get_varint_size(const varint_t v)
{
    size_t res = 0;
    
    unsigned char buf[100];
    res = kyk_pack_varint(buf, v);

    return res;
}


size_t get_var_str_size(const var_str* vstr)
{
    return get_varint_size(vstr -> len) + vstr -> len;
}

size_t kyk_pack_var_str(uint8_t* buf, const var_str* vstr)
{
    uint8_t* bufp = buf;

    bufp += kyk_pack_varint(bufp, vstr -> len);
    memcpy(bufp, vstr -> data, vstr -> len);
    bufp += vstr -> len;

    return bufp - buf;
}


var_str* kyk_new_var_str(const char* str)
{
    var_str* vstr = NULL;

    vstr = calloc(1, sizeof(*vstr));
    check(vstr, "Failed to kyk_new_var_str: calloc failed");

    vstr -> len = strlen(str);
    vstr -> data = calloc(vstr -> len + 1, sizeof(vstr -> data));
    check(vstr -> data, "Failed to kyk_new_var_str: calloc failed");

    strcpy(vstr -> data, str);

    return vstr;

error:

    return NULL;
}

void kyk_free_var_str(var_str* vstr)
{
    if(vstr){
	if(vstr -> data){
	    free(vstr -> data);
	    vstr -> data = NULL;
	}

	free(vstr);
    }
}
