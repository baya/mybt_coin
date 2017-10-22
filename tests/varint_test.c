#include "test.h"
#include "varint.h"

static int varfmt_cmp(const unsigned char *buf, const char *rhs, size_t len);

int main(void)
{
    size_t i = 0;
    varint_t v1 = 123;
    varint_t v3 = 515;
    varint_t v5 = 0x234567ab;
    varint_t v9 = 0x12345678a1a2a3a4;
    varint_t val;
    unsigned char buf[9];

    i = kyk_pack_varint(buf, v1);
    assert(i == 1);
    assert(varfmt_cmp(buf, "0x7b", 1) == 0);

    i = kyk_unpack_varint(buf, &val);
    assert(i == 1);
    assert(val == v1);
    
    i = kyk_pack_varint(buf, v3);
    assert(i == 3);
    assert(varfmt_cmp(buf, "0xfd0302", 3) == 0);

    i = kyk_unpack_varint(buf, &val);
    assert(i == 3);
    assert(val == v3);

    i = kyk_pack_varint(buf, v5);
    assert(i == 5);
    assert(varfmt_cmp(buf, "0xfeab674523", 5) == 0);

    i = kyk_unpack_varint(buf, &val);
    assert(i == 5);
    assert(val == v5);

    i = kyk_pack_varint(buf, v9);
    assert(i == 9);
    assert(varfmt_cmp(buf, "0xffa4a3a2a178563412", 9) == 0);

    i = kyk_unpack_varint(buf, &val);
    assert(i == 9);
    assert(val == v9);
    
}

static int varfmt_cmp(const unsigned char *buf, const char *rhs, size_t len)
{
    unsigned char hex_buf[100] = {0};
    unsigned char *p = hex_buf;
    int res;

    p += sprintf((char *)p, "0x");
    for(int i=0; i < len; i++){
	p += sprintf((char *)p, "%02x", buf[i]);
    }

    res = strcmp((char *)hex_buf, rhs);

    return res;
}
