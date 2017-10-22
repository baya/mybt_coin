#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "kyk_utils.h"
#include "kyk_script.h"

#define KYK_SC_MAX_LEN 1000

int main()
{
    unsigned char sc[KYK_SC_MAX_LEN];
    char *addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    size_t len;

    /* 从比特币地址中提取 pay-to-pubkey-hash 脚本 */
    len = p2pkh_sc_from_address(sc, addr);

    kyk_print_hex("scriptPubKey Hex ", sc, len);

}
