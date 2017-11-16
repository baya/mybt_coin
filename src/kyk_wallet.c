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
#include "kyk_ldb.h"
#include "kyk_blk_file.h"
#include "kyk_ser.h"
#include "kyk_buff.h"
#include "kyk_key.h"
#include "kyk_file.h"
#include "kyk_config.h"
#include "kyk_wallet.h"
#include "dbg.h"

#define WCFG_NUM_KEYS "numKeys"

const static char* BLOCKS_DIR =  "blocks";
const static char*  IDX_DB_NAME = "index";


static void set_init_bval(struct kyk_bkey_val *bval,
			  const struct kyk_block* blk,
			  const struct kyk_blk_file* blk_file
    );

static int kyk_load_wallet_cfg(struct kyk_wallet* wallet);

static int load_init_data_to_wallet(struct kyk_wallet *wallet);
static int kyk_set_fdir(const char* fdir);
struct kyk_wallet* new_wallet(const char *wdir);
int kyk_save_blk_to_file(struct kyk_blk_file* blk_file,
			 const struct kyk_block* blk
    );

int kyk_wallet_get_cfg_idx(struct kyk_wallet* wallet, int* cfg_idx);

struct kyk_wallet* kyk_init_wallet(const char *wdir)
{
    int res = -1;
    struct kyk_wallet* wallet = NULL;
    
    res = kyk_set_fdir(wdir);
    check(res == 0, "failed to kyk_set_fdir");
    
    wallet = new_wallet(wdir);
    check(wallet != NULL, "failed to get a new wallet");

    res = kyk_set_fdir(wallet -> blk_dir);
    check(res == 0, "failed to kyk_set_fdir");
    
    kyk_init_store_db(wallet -> blk_index_db, wallet -> idx_db_path);
    check(wallet -> blk_index_db -> errptr == NULL, "failed to init block index db");
    
    res = load_init_data_to_wallet(wallet);
    check(res > 0, "failed to init wallet");
    
    return wallet;
    
error:
    if(wallet) kyk_destroy_wallet(wallet);
    return NULL;
}

struct kyk_wallet* new_wallet(const char *wdir)
{
    struct kyk_wallet* wallet = (struct kyk_wallet*)malloc(sizeof(struct kyk_wallet));
    check(wallet != NULL, "failed to malloc wallet");
    
    wallet -> blk_index_db = (struct kyk_block_db*)malloc(sizeof(struct kyk_block_db));
    check(wallet -> blk_index_db != NULL, "failed to malloc block index db");
    
    wallet -> wdir = (char*)malloc(strlen(wdir) + 1);
    check(wallet -> wdir != NULL, "failed to malloc wdir");
    strncpy(wallet -> wdir, wdir, strlen(wdir) + 1);

    wallet -> blk_dir = kyk_pth_concat(wallet -> wdir, BLOCKS_DIR);
    check(wallet -> blk_dir != NULL, "failed to get block dir");
    
    wallet -> idx_db_path = kyk_pth_concat(wallet -> blk_dir, IDX_DB_NAME);
    check(wallet -> idx_db_path != NULL, "failed to get idx db path");

    return wallet;

error:
    if(wallet) kyk_destroy_wallet(wallet);
    return NULL;
}

int kyk_set_fdir(const char* fdir)
{
    int res = -1;
    
    if(kyk_detect_dir(fdir) != 1){
	res = kyk_file_mkdir(fdir);
	check(res == 0, "failed to kyk_file_mkdir");
    }

    return 0;

error:
    return -1;
}

struct kyk_wallet* kyk_open_wallet(const char *wdir)
{
    struct kyk_wallet* wallet = new_wallet(wdir);
    check(wallet != NULL, "failed to get a new wallet");

    kyk_init_store_db(wallet -> blk_index_db, wallet -> idx_db_path);
    check(wallet -> blk_index_db -> errptr == NULL, "failed to open block index db");
    
    return wallet;
    
error:
    if(wallet) kyk_destroy_wallet(wallet);    
    return NULL;
}

struct kyk_bkey_val* w_get_bval(const struct kyk_wallet* wallet, const char* blk_hash_str, char **errptr)
{
    //struct kyk_block* blk;
    struct kyk_bkey_val* bval = NULL;
    char blk_hash[32];
    size_t len = strlen(blk_hash_str);
    check(len == 64, "invalid block hash");

    kyk_parse_hex((uint8_t*)blk_hash, blk_hash_str);
    bval = kyk_read_block(wallet -> blk_index_db, blk_hash, errptr);

    return bval;
error:
    if(bval) kyk_free_bval(bval);
    return NULL;
}


void kyk_destroy_wallet(struct kyk_wallet* wallet)
{
    if(wallet -> wdir) free(wallet -> wdir);
    if(wallet -> blk_dir) free(wallet -> blk_dir);
    if(wallet -> idx_db_path) free(wallet -> idx_db_path);
    if(wallet -> blk_index_db) kyk_free_block_db(wallet -> blk_index_db);
}

int load_init_data_to_wallet(struct kyk_wallet *wallet)
{
    struct kyk_block *blk = NULL;
    struct kyk_bkey_val bval;
    struct kyk_blk_file* blk_file = NULL;
    int res = 1;
    char *errptr = NULL;
    
    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");

    blk_file = kyk_create_blk_file(0, wallet -> blk_dir, "ab");
    check(blk_file != NULL, "failed to create block file");

    res = kyk_save_blk_to_file(blk_file, blk);
    check(res == 1, "failed to save block to file");
    
    set_init_bval(&bval, blk, blk_file);
    kyk_store_block(wallet -> blk_index_db, &bval, &errptr);
    check(errptr == NULL, "failed to store b key value");

    kyk_free_block(blk);
    kyk_close_blk_file(blk_file);
    
    return res;

error:
    if(blk) kyk_free_block(blk);
    if(blk_file) kyk_close_blk_file(blk_file);
    return -1;
}

void set_init_bval(struct kyk_bkey_val *bval,
		   const struct kyk_block* blk,
		   const struct kyk_blk_file* blk_file
    )
{
    bval -> wVersion = 1;
    bval -> nHeight = 0;
    bval -> nStatus = BLOCK_HAVE_MASK;
    bval -> nTx = blk -> tx_count;
    bval -> nFile = blk_file -> nFile;
    bval -> nDataPos = blk_file -> nStartPos;
    bval -> nUndoPos = 0;
    bval -> blk_hd = blk -> hd;
}

int kyk_save_blk_to_file(struct kyk_blk_file* blk_file,
			   const struct kyk_block* blk
    )
{
    struct kyk_buff* buf = NULL;
    size_t len = 0;
    long int pos = 0;

    buf = create_kyk_buff(1000);
    check(buf != NULL, "failed to create kyk buff");
    
    len = kyk_ser_blk_for_file(buf, blk);
    check(len > 0, "failed to serialize block");
    
    pos = ftell(blk_file -> fp);
    check(pos != -1L, "failed to get the block dat file pos");

    blk_file -> nOffsetPos = sizeof(blk -> magic_no) + sizeof(blk -> blk_size);
    
    blk_file -> nStartPos = (unsigned int)pos + blk_file -> nOffsetPos;
    
    len = fwrite(buf -> base, sizeof(uint8_t), buf -> len, blk_file -> fp);
    check(len == buf -> len, "failed to save block to file");
    blk_file -> nEndPos = len;
    

    free_kyk_buff(buf);
    return 1;
error:
    if(buf) free_kyk_buff(buf);
    return -1;
}

struct kyk_wallet_key* kyk_create_wallet_key(uint32_t cfg_idx,
					     const char* desc
    )
{
    struct kyk_wallet_key* wkey = NULL;
    struct kyk_key* k = NULL;
    uint8_t* privkey = NULL;
    uint8_t* pubkey = NULL;
    char* privStr = NULL;
    char* btc_addr = NULL;
    size_t len = 0;
    int res = -1;

    k = kyk_key_generate_new();
    check(k != NULL, "failed to kyk_key_generate_new");
    
    kyk_key_get_privkey(k, &privkey, &len);
    check(len > 0, "failed to kyk_key_get_privkey");
    privStr = kyk_base58check(PRIVKEY_ADDRESS, privkey, len);
    btc_addr = kyk_make_address_from_pub(k -> pub_key, k -> pub_len);

    wkey = calloc(1, sizeof *wkey);
    check(wkey != NULL, "failed to calloc");
    
    wkey -> cfg_idx = cfg_idx;
    wkey -> desc = desc ? kyk_strdup(desc) : NULL;
    wkey -> priv_str = privStr;
    wkey -> btc_addr = btc_addr;
    wkey -> pub_key = pubkey;
    res = kyk_key_cpy_pubkey(k, &wkey -> pub_key, &wkey -> pub_len);
    check(res == 0, "failed to kyk_cpy_pubkey");

    return wkey;
    
error:
    if(k) free_kyk_key(k);
    if(privkey) free(privkey);
    if(btc_addr) free(btc_addr);
    if(pubkey) free(pubkey);
    
    return NULL;

}

int kyk_wallet_get_cfg_idx(struct kyk_wallet* wallet, int* cfg_idx)
{
    int res = -1;
    struct config* w_cfg = NULL;

    if(wallet -> wallet_cfg == NULL){
	res = kyk_load_wallet_cfg(wallet);
	check(0 == res, "failed to kyk_load_wallet_cfg");
    }

    w_cfg = wallet -> wallet_cfg;

    res = kyk_config_get_cfg_idx(w_cfg, cfg_idx);
    check(res == 0, "failed to kyk_config_get_cfg_idx");

    return 0;

error:

    return -1;

}

int kyk_load_wallet_cfg(struct kyk_wallet* wallet)
{
    struct config* cfg = NULL;
    int res = -1;

    check(wallet, "wallet can not be NULL");
    check(wallet -> wallet_cfg_path, "wallet cfg path can not be NULL");
    check(wallet -> wallet_cfg == NULL, "wallet cfg has already been loaded");

    res = kyk_config_load(wallet -> wallet_cfg_path, &cfg);
    check(res == 0, "failed to kyk_config_load");

    wallet -> wallet_cfg = cfg;

    return 0;

error:

    return -1;
}


int kyk_wallet_add_key(struct kyk_wallet* wallet,
		       struct kyk_wallet_key* k)
{
    int res = -1;
    struct config* w_cfg = NULL;
    char pubStr[256];
    
    if(wallet -> wallet_cfg == NULL){
	res = kyk_load_wallet_cfg(wallet);
	check(res == 0, "failed to kyk_load_wallet_cfg");	
    }

    w_cfg = wallet -> wallet_cfg;

    res = str_snprintf_bytes(pubStr, sizeof(pubStr), k -> pub_key, k -> pub_len);
    check(res == 0, "failed to str_snprintf_bytes");
    
    res = kyk_config_setstring(w_cfg, k -> desc, "key%u.desc", k -> cfg_idx);
    check(res == 0, "failed to kyk_config_setstring");
    
    res = kyk_config_setstring(w_cfg, k -> priv_str, "key%u.privkey", k -> cfg_idx);
    check(res == 0, "failed to kyk_config_setstring");
    
    res = kyk_config_setstring(w_cfg, pubStr, "key%u.pubkey", k -> cfg_idx);
    check(res == 0, "failed to kyk_config_setstring");
    
    res = kyk_config_setstring(w_cfg, k -> btc_addr, "key%u.address", k -> cfg_idx);
    check(res == 0, "failed to kyk_config_setstring");

    res = kyk_config_write(w_cfg, wallet -> wallet_cfg_path);
    check(res == 0, "failed to kyk_config_write");

    return 0;

error:
    
    return -1;
}

int kyk_wallet_add_address(struct kyk_wallet* wallet, const char* desc)
{
    int res = -1;
    int idx = -1;
    struct kyk_wallet_key* k = NULL;

    check(wallet, "wallet can not be NULL");
    check(desc, "address desc can not be NULL");

    res = kyk_wallet_get_cfg_idx(wallet, &idx);
    check(res == 0, "failed to kyk_wallet_get_cfg_idx");

    k = kyk_create_wallet_key(idx, desc);
    check(k, "failed to kyk_create_wallet_key");

    res = kyk_wallet_add_key(wallet, k);
    check(res == 0, "failed to kyk_wallet_add_key");

    kyk_destroy_wallet_key(k);

    return 0;
    
error:

    kyk_destroy_wallet_key(k);
    return -1;
}


int kyk_wallet_check_config(struct kyk_wallet* wallet, const char* wdir)
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

    if(!kyk_file_exists(main_cfg_path)){
	printf("\nIt looks like you're a new user. Welcome!\n"
	       "\n"
	       "Note that kyk_miner uses the directory: %s to store:\n"
	       " - blocks:               %s/blocks     \n"
	       " - peer IP addresses:    %s/peers.dat  \n"
	       " - transaction database: %s/txdb       \n"
	       " - wallet keys:          %s/wallet.cfg \n"
	       " - main config file:     %s/main.cfg \n\n",
	       wdir,
	       wdir,
	       wdir,
	       wdir,
	       wdir,
	       wdir
	    );

    } else {
	/* printf("exit, node files are already in %s\n", wdir); */
	/* exit(0); */
    }

    if(!kyk_file_exists(wdir)){
	res = kyk_file_mkdir(wdir);
	check(res == 0, "Failed to create directory '%s'", wdir);

	res = kyk_file_chmod(wdir, 0700);
	check(res == 0, "Failed to chmod 0700 direcotry '%s'", wdir);
    }

    wallet -> wdir = kyk_strdup(wdir);

    res = kyk_check_create_file(peers_dat_path, "peers");
    check(res == 0, "Failed to kyk_check_create_file '%s'", peers_dat_path);
    
    kyk_check_create_file(txdb_path, "txdb");
    check(res == 0, "Failed to kyk_check_create_file '%s'", txdb_path);
    
    kyk_check_create_file(wallet_cfg_path, "wallet config");
    check(res == 0, "Failed to kyk_check_create_file '%s'", wallet_cfg_path);
    wallet -> wallet_cfg_path = wallet_cfg_path;
    
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


void kyk_destroy_wallet_key(struct kyk_wallet_key* k)
{
    if(k == NULL){
	return;
    }

    if(k -> key) free_kyk_key(k -> key);
    if(k -> priv_str) free(k -> priv_str);
    if(k -> desc) free(k -> desc);
    if(k -> btc_addr) free(k -> btc_addr);
    if(k -> pub_key) free(k -> pub_key);
}

