#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kyk_utils.h"
#include "kyk_address.h"
#include "kyk_buff.h"
#include "kyk_script.h"
#include "kyk_ecdsa.h"

int match_cmd(char *src, char *cmd);

int main(int argc, char* argv[])
{
    if(argc == 3){
	if(match_cmd(argv[1], "getAddr")){
	    uint8_t* pub;
	    size_t len;
	    char* addr;
	    pub = kyk_alloc_hex(argv[2], &len);
	    addr = kyk_make_address_from_pubkey(pub, len);
	    printf("got address: %s\n", addr);
	} else if(match_cmd(argv[1], "getScriptPubkey")){
	    uint8_t* pub;
	    size_t len;
	    struct kyk_buff* sc;

	    pub = kyk_alloc_hex(argv[2], &len);
	    build_p2pkh_sc_from_pubkey(pub, len, &sc);
	    kyk_print_hex("ScriptPubkey", sc -> base, sc -> len);
        } else if(match_cmd(argv[1], "getPubkey")) {
	    uint8_t* priv;
	    size_t len;
	    struct kyk_buff* pub;

	    priv = kyk_alloc_hex(argv[2], &len);

	    kyk_ec_get_pubkey_from_priv(priv, 1, &pub);
	    kyk_print_hex("PubKey", pub -> base, pub -> len);
	} else {
	    printf("invalid options\n");
	}
    } else {
	printf("invalid options\n");
    }
    
    return 0;
}

int match_cmd(char *src, char *cmd)
{
    int res = 0;
    
    res = strcasecmp(src, cmd) == 0 ? 1 : 0;

    return res;
}
