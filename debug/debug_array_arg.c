#include <stdio.h>
#include <stdlib.h>

void pp_arr(const uint8_t a[4])
{
    printf("???%lu\n", sizeof(a));
    printf("+++++%lu\n", sizeof(uint8_t));
    a++;
    printf("*****%d\n", *++a);
}

int main()
{
    uint8_t a[3] = {0,1,2};
    uint8_t b[4] = {0,1,2,3};

    //printf("@@@@@@%lu\n", sizeof(a));
    //printf("@@@@@@%lu\n", sizeof(b));
    pp_arr(a);
    pp_arr(b);

}
