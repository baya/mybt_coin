#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "kyk_utils.h"
#include "dbg.h"

uint64_t read_varint(const uint8_t *buf, size_t len);

int main()
{
    unsigned char *hexstr = "889271cd101d0100808cbf1199b747";

    uint8_t *buf;
    size_t buf_len = 0;

    buf = kyk_alloc_hex(hexstr, &buf_len);
    kyk_print_hex("buf", buf, buf_len);
    uint64_t res = read_varint(buf, buf_len);
    printf("+++++++++%llu\n", res);

}

uint64_t read_varint(const uint8_t *buf, size_t len)
{
    uint64_t n = 0;
    int i = 0;

    while(i < len) {
        unsigned char chData = *buf;
	buf++;
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80) {
            n++;
        } else {
            return n;
        }
	i++;
    }

}
