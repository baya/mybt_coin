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
#include "kyk_block.h"
#include "kyk_validate.h"
#include "kyk_utxo.h"
#include "kyk_address.h"
#include "dbg.h"

#define WALLET_NAME ".kyk_miner"


#define CMD_INIT           "init"
#define CMD_DELETE         "delete"
#define CMD_ADD_ADDRESS    "addAddress"
#define CMD_QUERY_BLOCK    "queryBlock"
#define CMD_MK_BLOCK       "makeBlock"
#define CMD_QUERY_BALANCE  "queryBalance"
#define CMD_SHOW_ADDR_LIST "showAddrList"
#define CMD_MK_TX          "makeTx"
#define CMD_SERVE          "serve"

int match_cmd(char *src, char *cmd);
int cmd_add_address(struct kyk_wallet* wallet, const char* desc);
int cmd_make_block(const struct kyk_wallet* wallet);
int cmd_query_balance(const struct kyk_wallet* wallet);
int cmd_show_addr_list(const struct kyk_wallet* wallet);

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
	printf("init a wallet:     %s %s\n", argv[0], CMD_INIT);
	printf("make init blocks:  %s %s\n", argv[0], CMD_MK_BLOCK);
	printf("make tx:           %s %s\n", argv[0], CMD_MK_TX);
	printf("query blance:      %s %s\n", argv[0], CMD_QUERY_BALANCE);
	printf("show address list: %s %s\n", argv[0], CMD_SHOW_ADDR_LIST);
	printf("start server:      %s %s\n", argv[0], CMD_SERVE);
	printf("add address:       %s %s [address label]\n", argv[0], CMD_ADD_ADDRESS);
	printf("query block:       %s %s [block hash]\n", argv[0], CMD_QUERY_BLOCK);
	printf("delete wallet:     %s %s\n", argv[0], CMD_DELETE);
    }
    
    if(argc == 2){
	if(match_cmd(argv[1], CMD_INIT)){
	    if(kyk_file_exists(wdir)){
		printf("wallet is already in %s\n", wdir);
		return 0;
	    }
	    res = kyk_setup_wallet(&wallet, wdir);
	    check(res == 0, "Failed to init wallet: kyk_setup_wallet failed");
	    check(wallet, "Failed to init wallet: kyk_setup_wallet failed");
	} else if(match_cmd(argv[1], CMD_DELETE)){
	    printf("please use system command `rm -rf %s` to delete wallet\n", wdir);
	} else if(match_cmd(argv[1], CMD_MK_BLOCK)){
	    wallet = kyk_open_wallet(wdir);
	    check(wallet, "Failed to kyk_open_wallet");
	    cmd_make_block(wallet);
	} else if(match_cmd(argv[1], CMD_QUERY_BALANCE)){
	    wallet = kyk_open_wallet(wdir);
	    cmd_query_balance(wallet);
	} else if(match_cmd(argv[1], CMD_SHOW_ADDR_LIST)){
	    wallet = kyk_open_wallet(wdir);
	    cmd_show_addr_list(wallet);
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

    if(argc == 4){
	if(match_cmd(argv[1], CMD_MK_TX)){
	    wallet = kyk_open_wallet(wdir);
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

int cmd_make_block(const struct kyk_wallet* wallet)
{

    int res = -1;
    
    res = kyk_wallet_make_coinbase_block(NULL, wallet);
    check(res == 0, "Failed to cmd_make_block: kyk_wallet_make_coinbase_block failed");
    
    return 0;

error:
    return -1;
}

int cmd_query_balance(const struct kyk_wallet* wallet)
{
    uint64_t value = 0;
    double balance = 0.0;
    int res = -1;

    res = kyk_wallet_query_total_balance(wallet, &value);
    check(res == 0, "Failed to cmd_query_balance: kyk_wallet_query_total_balance failed");

    balance = value / ONE_BTC_COIN_VALUE;

    printf("%f BTC\n", balance);


    return 0;
    
error:

    return -1;
}

int cmd_show_addr_list(const struct kyk_wallet* wallet)
{
    char** addr_list = NULL;
    size_t len = 0;
    size_t i = 0;
    int res = -1;

    check(wallet, "Failed to cmd_show_addr_list: wallet is NULL");

    res = kyk_wallet_load_addr_list(wallet, &addr_list, &len);
    check(res == 0, "Failed to cmd_show_addr_list: kyk_wallet_load_addr_list failed");
    
    for(i = 0; i < len; i++){
	printf("%s\n", addr_list[i]);
    }

    return 0;

error:

    return -1;
}

int cmd_make_tx(const struct kyk_wallet* wallet,
		int btc_num,
		const char* btc_addr)
{
    int res = -1;

    res = kyk_wallet_cmd_make_tx(wallet, btc_num, btc_addr);
    check(res == 0, "Failed to cmd_make_tx");

    return 0;
    
error:

    return -1;
}

