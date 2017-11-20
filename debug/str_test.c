#include <stdio.h>
#include <string.h>

int main()
{
    char msg2[10] = "0123456789aaa";

    printf("sizeof: %zu\n", sizeof(msg2));
    printf("length: %lu\n", strlen(msg2));
    printf("%s\n", msg2);
}
