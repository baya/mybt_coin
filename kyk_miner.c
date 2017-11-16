#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "kyk_utils.h"
#include "gens_block.h"
#include "block_store.h"
#include "kyk_wallet.h"
#include "kyk_file.h"
#include "dbg.h"

#define WALLET_NAME ".kyk_miner"
#define MAIN_ADDR_LABEL "Main Miner Address"

#define CMD_INIT        "init"
#define CMD_DELETE      "delete"
#define CMD_ADD_ADDRESS "addAddress"
#define CMD_QUERY_BLOCK "queryBlock"

int match_cmd(char *src, char *cmd);
int set_main_address(struct kyk_wallet* wallet);
int cmd_add_address(struct kyk_wallet* wallet, const char* desc);

int main(int argc, char *argv[])
{
    struct kyk_wallet* wallet = NULL;
    char *hmdir = NULL;
    char *wdir = NULL;
    char *errptr = NULL;
    int res = -1;

    hmdir = kyk_gethomedir();
    check(hmdir != NULL, "failed to find the current dir");
    wdir = kyk_pth_concat(hmdir, WALLET_NAME);
    check(wdir != NULL, "failed to find the wallet dir");

    if(argc == 1){
	printf("usage: %s command [args]\n", argv[0]);
	printf("init a wallet: %s " CMD_INIT "\n", argv[0]);
	printf("add address: %s " CMD_ADD_ADDRESS "\n", argv[0]);
	printf("query block: %s " CMD_QUERY_BLOCK "[block hash]\n", argv[0]);
	printf("delete wallet: %s " CMD_DELETE "\n", argv[0]);
    }
    
    if(argc == 2){
	if(match_cmd(argv[1], "init")){
	    wallet = kyk_init_wallet(wdir);
	    check(wallet != NULL, "failed to init wallet");
	    kyk_wallet_check_config(wallet, wdir);
	    res = set_main_address(wallet);
	    check(res == 0, "failed to set_main_address");
	} else if(match_cmd(argv[1], "delete")){
	    printf("please use system command `rm -rf %s` to delete wallet\n", wdir);
	} else {
	    printf("invalid options\n");
	}
    }

    if(argc == 3){
	if(match_cmd(argv[1], CMD_QUERY_BLOCK)){
	    struct kyk_bkey_val* bval = NULL;
	    wallet = kyk_open_wallet(wdir);
	    check(wallet != NULL, "failed to open wallet");
	    bval = w_get_bval(wallet, argv[2], &errptr);
	    check(errptr == NULL, "failed to getblock %s", errptr);
	    if(bval == NULL){
		printf("No block record found\n");
	    } else {
		kyk_print_bval(bval);
		kyk_free_bval(bval);
	    }
	} else if(match_cmd(argv[1], CMD_ADD_ADDRESS)){
	    wallet = kyk_open_wallet(wdir);
	    check(wallet, "failed to open wallet");
	    res = kyk_wallet_check_config(wallet, wdir);
	    check(res == 0, "failed to kyk_wallet_check_config");
	    cmd_add_address(wallet, argv[2]);
	} else {
	    printf("invalid command %s\n", argv[1]);
	}
    }

    if(wdir) free(wdir);
    if(wallet) kyk_destroy_wallet(wallet);
    
    return 0;

error:
    if(wdir) free(wdir);
    if(wallet) kyk_destroy_wallet(wallet);
    return -1;
}

int match_cmd(char *src, char *cmd)
{
    int res = 0;
    
    res = strcasecmp(src, cmd) == 0 ? 1 : 0;

    return res;
}

int set_main_address(struct kyk_wallet* wallet)
{
    int res = -1;

    res = kyk_wallet_add_address(wallet, MAIN_ADDR_LABEL);
    check(res == 0, "failed to kyk_wallet_add_address");
    
    return 0;

error:

    return -1;
}

int cmd_add_address(struct kyk_wallet* wallet, const char* desc)
{
    int res = -1;
    
    check(wallet, "wallet can not be NULL");
    check(desc, "address desc can not be NULL");
    
    res = kyk_wallet_add_address(wallet, desc);
    check(res == 0, "failed to kyk_wallet_add_address");

    return 0;

error:

    exit(1);
}

