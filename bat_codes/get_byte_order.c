#include <stdio.h>


int main()
{
    int a;
    char b;
    a = 1;
    b = *((char*)&a);
    if(b)
    {
        printf("little !\n");
    }
    else
    {
        printf("big !\n");
    }
}