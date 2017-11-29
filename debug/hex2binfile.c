#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint8_t kyk_hex2byte(const char ch);

int main(void)
{
    const char* blkfile = "blk777.txt";
    const char* blk_binfile = "blk_777tx_00000000000000001544f99d2e133956f5352feabba910ff64d0d87b16daa26c.dat";
    FILE* fp = fopen(blkfile, "r");
    uint8_t buf[1000000];

    if(!fp) {
        perror("File opening failed");
        return EXIT_FAILURE;
    }

    int c;
    int i = 0;
    size_t len = 0;
    char hi, lo;
    
    while ((c = fgetc(fp)) != EOF) { // standard C I/O file reading loop
	//putchar(c);
       if(i % 2 == 0){
	   hi = kyk_hex2byte(c);
       } else {
	   lo = kyk_hex2byte(c);
	   buf[len] = hi * 16 + lo;
	   len++;
       }
       i++;
    }

    size_t r1;
    FILE* fp2 = fopen(blk_binfile, "wb");
    r1 = fwrite(buf, sizeof(buf[0]), len, fp2);
    printf("wrote %zu elements out of %zu requested\n", r1, len);

    fclose(fp2);

    if (ferror(fp))
        puts("I/O error when reading");
    else if (feof(fp))
        puts("End of file reached successfully");
 
    fclose(fp);
}

uint8_t kyk_hex2byte(const char ch)
{
    if ((ch >= '0') && (ch <= '9')) {
        return ch - '0';
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + 10;
    }
    return 0;
}

