#include <stdio.h>
#include <stdlib.h>

void pp_arr(const uint8_t a[])
{
    printf("???%lu\n", sizeof(a));
    printf("+++++%lu\n", sizeof(uint8_t));
    a++;
    printf("*****%d\n", *++a);
}

int main()
{
    uint8_t a[11] = {0,1,2,3,4,5,6,7,8,9,10};
    uint8_t b[4] = {0,1,2,3};

    printf("@@@@@@%lu\n", sizeof(a));
    //printf("@@@@@@%lu\n", sizeof(b));
    pp_arr(a);
    pp_arr(b);

}
