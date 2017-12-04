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


#define CMD_INIT           "init"
#define CMD_DELETE         "delete"
#define CMD_ADD_ADDRESS    "addAddress"
#define CMD_QUERY_BLOCK    "queryBlock"
#define CMD_MK_INIT_BLOCKS "makeInitBlocks"
#define CMD_MK_TX          "makeTx"
#define CMD_Q_BALANCE      "queryBalance"
#define CMD_SERVE          "serve"

int match_cmd(char *src, char *cmd);
int cmd_add_address(struct kyk_wallet* wallet, const char* desc);
int cmd_make_init_blocks(const struct kyk_wallet* wallet);

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
	printf("init a wallet:    %s %s\n", argv[0], CMD_INIT);
	printf("make init blocks: %s %s\n", argv[0], CMD_MK_INIT_BLOCKS);
	printf("make tx:          %s %s\n", argv[0], CMD_MK_TX);
	printf("query blance:     %s %s\n", argv[0], CMD_Q_BALANCE);
	printf("start server:     %s %s\n", argv[0], CMD_SERVE);
	printf("add address:      %s %s\n", argv[0], CMD_ADD_ADDRESS);
	printf("query block:      %s %s [block hash]\n", argv[0], CMD_QUERY_BLOCK);
	printf("delete wallet:    %s %s\n", argv[0], CMD_DELETE);
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
	} else if(match_cmd(argv[1], CMD_MK_INIT_BLOCKS)){
	    wallet = kyk_open_wallet(wdir);
	    cmd_make_init_blocks(wallet);
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

int cmd_make_init_blocks(const struct kyk_wallet* wallet)
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_tx* tx = NULL;
    struct kyk_blk_header* hd = NULL;
    struct kyk_blk_header* hd_list = NULL;
    struct kyk_blk_header* hd_tail = NULL;
    const char* note = "void coin";
    uint64_t btc_count = 100;
    uint64_t outValue = ONE_BTC_COIN_VALUE * btc_count;
    uint8_t* pubkey = NULL;
    size_t pbk_len = 0;
    uint8_t pre_blk_hash[32];
    uint32_t tts;
    uint32_t bts;
    int res = -1;

    uint8_t buf[80];

    res = kyk_wallet_get_pubkey(&pubkey, &pbk_len, wallet, "key0.pubkey");
    check(res == 0, "Failed to cmd_make_init_blocks: kyk_wallet_get_pubkey failed");

    res = kyk_make_coinbase_tx(&tx, note, outValue, pubkey, pbk_len);
    check(res == 0, "Failed to cmd_make_init_blocks: kyk_make_coinbase_tx failed");

    res = kyk_load_blk_header_chain(&hd_chain, wallet);
    check(res == 0, "Failed to cmd_make_init_blocks: kyk_load_blk_header_chain failed");

    hd_list = hd_chain -> hd_list;
    hd_tail = hd_list + hd_chain -> len - 1;
    

    res = kyk_blk_hash256(pre_blk_hash, hd_tail);
    check(res == 0, "Failed to cmd_make_init_blocks: kyk_blk_hash256 failed");

    res = time(NULL);
    check(res != -1, "Failed to cmd_make_init_blocks: time Failed");
    tts = (uint32_t)res;
    bts = 0x1f00ffff;
    hd = kyk_make_blk_header(tx, 1, 1, pre_blk_hash, tts, bts);

    kyk_seri_blk_hd(buf, hd);
    printf("hd -> tts: %u\n", hd -> tts);
    kyk_print_hex("block header", buf, 80);
    
    return 0;

error:
    if(pubkey) free(pubkey);
    return -1;
}

