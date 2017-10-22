#include <stdio.h>

int main(void)
{
    const char hexstring[] = "deadbeef10203040b00b1e50", *pos = hexstring;
    unsigned char val[12];
    size_t count = 0;

    /* WARNING: no sanitization or error-checking whatsoever */
    for(count = 0; count < sizeof(val)/sizeof(val[0]); count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }

    printf("0x");
    for(count = 0; count < sizeof(val)/sizeof(val[0]); count++)
        printf("%02x", val[count]);
    printf("\n");

    return(0);
}
