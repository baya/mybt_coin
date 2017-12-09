#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    uint8_t a = 0xb1;

    uint64_t b = 0;

    b |= (uint64_t)a << 32;

    printf("????????? %0llx\n", b);
}
