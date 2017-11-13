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

static int kyk_check_config(const char* wdir);

int match_cmd(char *src, char *cmd);

int main(int argc, char *argv[])
{
    struct kyk_wallet* wallet = NULL;
    char *hmdir = NULL;
    char *wdir = NULL;
    char *errptr = NULL;

    hmdir = kyk_gethomedir();
    check(hmdir != NULL, "failed to find the current dir");
    wdir = kyk_pth_concat(hmdir, WALLET_NAME);
    check(wdir != NULL, "failed to find the wallet dir");

    if(argc == 1){
	printf("usage: %s command [args]\n", argv[0]);
	printf("init a wallet: %s init\n", argv[0]);
	printf("query block: %s getblock [block hash]\n", argv[0]);
	printf("delete wallet: %s delete\n", argv[0]);
    }
    
    if(argc == 2){
	if(match_cmd(argv[1], "init")){
	    kyk_check_config(wdir);
	    wallet = kyk_init_wallet(wdir);
	    check(wallet != NULL, "failed to init wallet");
	} else if(match_cmd(argv[1], "delete")){
	    printf("please use system command `rm -rf %s` to delete wallet\n", wdir);
	} else {
	    printf("invalid options\n");
	}
    }

    if(argc == 3){
	if(match_cmd(argv[1], "getblock")){
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
    size_t count = strlen(cmd);
    int res = 0;
    
    res = strncmp(src, cmd, count) == 0 ? 1 : 0;

    return res;
}

static int kyk_check_config(const char* wdir)
{
    char* peers_dat_path = NULL;
    char* txdb_path = NULL;
    char* wallet_cfg_path = NULL;
    char* main_cfg_path = NULL;
    int res = 0;

    peers_dat_path = kyk_asprintf("%s/peers.dat", wdir);
    txdb_path = kyk_asprintf("%s/txdb", wdir);
    wallet_cfg_path = kyk_asprintf("%s/wallet.cfg", wdir);
    main_cfg_path = kyk_asprintf("%s/main.cfg", wdir);

    if(!kyk_file_exists(wdir)){
	printf("\nIt looks like you're a new user. Welcome!\n"
	       "\n"
	       "Note that kyk_miner uses the directory: ~/"WALLET_NAME"to store:\n"
	       " - blocks:               ~/"WALLET_NAME"/blocks     \n"
	       " - peer IP addresses:    ~/"WALLET_NAME"/peers.dat  \n"
	       " - transaction database: ~/"WALLET_NAME"/txdb       \n"
	       " - wallet keys:          ~/"WALLET_NAME"/wallet.cfg \n"
	       " - main config file:     ~/"WALLET_NAME"/main.cfg \n\n");

    } else {
	printf("exit, node files are already in %s\n", wdir);
	exit(0);
    }

    if(!kyk_file_exists(wdir)){
	res = kyk_file_mkdir(wdir);
	check(res == 0, "Failed to create directory '%s'", wdir);

	res = kyk_file_chmod(wdir, 0700);
	check(res == 0, "Failed to chmod 0700 direcotry '%s'", wdir);
    }

    res = kyk_check_create_file(peers_dat_path, "peers");
    check(res == 0, "Failed to kyk_check_create_file '%s'", peers_dat_path);
    
    kyk_check_create_file(txdb_path, "txdb");
    check(res == 0, "Failed to kyk_check_create_file '%s'", txdb_path);
    
    kyk_check_create_file(wallet_cfg_path, "wallet config");
    check(res == 0, "Failed to kyk_check_create_file '%s'", wallet_cfg_path);
    
    kyk_check_create_file(main_cfg_path, "main config");
    check(res == 0, "Failed to kyk_check_create_file '%s'", main_cfg_path);
    

    return 0;

error:
    free(peers_dat_path);
    free(txdb_path);
    free(wallet_cfg_path);
    free(main_cfg_path);
    
    return -1;
}
