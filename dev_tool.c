#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kyk_utils.h"
#include "kyk_address.h"

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
