#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>


#include "kyk_utils.h"


int main()
{
    char *sig_hex = "3044022062f36c5cd1f9fdc7adb37ff9072270b8cbef48d41308c5cb2735781a22ca800b022075e04c4e1152376f3f11aaf5d3039eac29686d03e023356f543643221007609e";
    uint8_t *sig;
    const uint8_t *sig_cpy;
    size_t sig_len;

    ECDSA_SIG *signature;

    sig = kyk_alloc_hex(sig_hex, &sig_len);
    sig_cpy = sig;
    signature = d2i_ECDSA_SIG(NULL, &sig_cpy, sig_len);
    printf("R : %s\n", BN_bn2hex(signature->r));
    printf("S : %s\n", BN_bn2hex(signature->s));
}
