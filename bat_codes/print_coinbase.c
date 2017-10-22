#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_utils.h"


int main()
{
    //char *cb_hex = "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
    char *cb_hex = "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
    uint8_t *cb;
    uint8_t *cb_str;
    size_t cb_len;

    cb = kyk_alloc_hex(cb_hex, &cb_len);

    cb_str = calloc(cb_len + 1, sizeof(uint8_t));
    for(int i=0; i < cb_len; i++){
	cb_str[i] = cb[i];
    }

    cb_str[cb_len] = '\0';

    printf("%s\n", cb_str);
}
