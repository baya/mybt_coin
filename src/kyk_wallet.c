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
#include "beej_pack.h"
#include "kyk_utxo.h"
#include "kyk_wallet.h"
#include "kyk_validate.h"
#include "dbg.h"

#define WCFG_NUM_KEYS "numKeys"
#define MAIN_ADDR_LABEL "Main Miner Address"

static void set_init_bval(struct kyk_bkey_val *bval,
			  const struct kyk_block* blk,
			  const struct kyk_blk_file* blk_file);

static int kyk_load_wallet_cfg(struct kyk_wallet* wallet);

static int save_setup_data_to_wallet(struct kyk_wallet *wallet);
static int kyk_save_blk_to_file(struct kyk_blk_file* blk_file,
				const struct kyk_block* blk);

static int kyk_setup_main_address(struct kyk_wallet* wallet);

static int kyk_wallet_get_cfg_idx(struct kyk_wallet* wallet, int* cfg_idx);

static int get_address(const struct KeyValuePair* ev, char** new_addr);

static void free_addr_list(char** addr_list, size_t len);

int kyk_setup_spv_wallet(struct kyk_wallet** new_wallet, const char* wdir)
{
    int res = -1;

    res = kyk_setup_wallet(new_wallet, wdir);
    check(res == 0, "Failed to kyk_setup_spv_wallet: kyk_setup_wallet failed");
    
    return 0;
    
error:

    return -1;

}

int kyk_setup_wallet(struct kyk_wallet** outWallet, const char* wdir)
{
    struct kyk_wallet* wallet = NULL;
    int res = -1;
    
    check(outWallet, "Failed to kyk_setup_wallet: wallet is NULL");
    check(wdir, "Failed to kyk_setup_wallet: wdir is NULL");

    wallet = kyk_new_wallet(wdir);
    check(wallet, "Failed to kyk_setup_wallet: kyk_new_wallet failed");

    res = kyk_init_wallet(wallet);
    check(res == 0, "Failed to kyk_setup_wallet: kyk_init_wallet failed");

    res = save_setup_data_to_wallet(wallet);
    check(res == 0, "failed to init wallet");

    res = kyk_setup_main_address(wallet);
    check(res == 0, "Failed to kyk_setup_wallet: kyk_setup_main_address failed");

    res = kyk_load_wallet_cfg(wallet);
    check(res == 0, "Failed to kyk_setup_wallet: kyk_load_wallet_cfg failed");

    *outWallet = wallet;

    return 0;

error:

    if(wallet) kyk_destroy_wallet(wallet);
    return -1;

}

int kyk_setup_main_address(struct kyk_wallet* wallet)
{
    int res = -1;

    res = kyk_wallet_add_address(wallet, MAIN_ADDR_LABEL);
    check(res == 0, "Failed to kyk_setup_main_address: kyk_wallet_add_address failed");

    return 0;
    
error:

    return -1;
}


struct kyk_wallet* kyk_open_wallet(const char *wdir)
{
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    check(wdir, "Failed to kyk_open_wallet: wdir is NULL");
    check(kyk_file_exists(wdir), "Failed to kyk_open_wallet: wallet is not existed, please setup wallet firstly");

    wallet = kyk_new_wallet(wdir);
    check(wallet, "Failed to kyk_open_wallet: kyk_new_wallet failed");

    res = kyk_init_wallet(wallet);
    check(res == 0, "Failed to kyk_open_wallet: kyk_init_wallet failed");

    return wallet;
    
error:
    if(wallet) kyk_destroy_wallet(wallet);    
    return NULL;
}

struct kyk_wallet* kyk_new_wallet(const char *wdir)
{
    struct kyk_wallet* wallet = NULL;
    int res = -1;

    check(wdir, "Failed to kyk_new_wallet: wdir is NULL");
    
    wallet = calloc(1, sizeof *wallet);
    check(wallet , "Failed to kyk_new_wallet: wallet calloc failed");

    res = kyk_wallet_check_config(wallet, wdir);
    check(res == 0, "Failed to kyk_new_wallet: kyk_wallet_check_config failed");
    
    return wallet;

error:
    if(wallet) kyk_destroy_wallet(wallet);
    return NULL;
}

int kyk_init_wallet(struct kyk_wallet* wallet)
{
    int res = -1;

    struct kyk_block_db* blk_inx_db = NULL;

    check(wallet, "Failed to kyk_init_wallet: wallet is NULL");
    check(wallet -> wdir, "Failed to kyk_init_wallet: wallet -> wdir is NULL");
    check(wallet -> idx_db_path, "Failed to kyk_init_wallet: wallet -> idx_db_path is NULL");

    blk_inx_db = calloc(1, sizeof *blk_inx_db);
    check(blk_inx_db, "Failed to kyk_init_wallet: blk_inx_db calloc failed");

    wallet -> blk_index_db = blk_inx_db;
    res = kyk_init_store_db(wallet -> blk_index_db, wallet -> idx_db_path);
    check(res == 0, "Failed to kyk_init_wallet: kyk_init_store_db failed");
    check(wallet -> blk_index_db -> errptr == NULL, "failed to init block index db");

    res = kyk_load_wallet_cfg(wallet);
    check(res == 0, "Failed to kyk_init_wallet: kyk_load_wallet_cfg failed");
    
    return 0;
    
error:
    if(blk_inx_db) kyk_free_block_db(blk_inx_db);
    return -1;
}



/* wallet config */
int kyk_wallet_check_config(struct kyk_wallet* wallet, const char* wdir)
{
    char* blk_dir = NULL;
    char* idx_db_path = NULL;
    char* peers_dat_path = NULL;
    char* txdb_path = NULL;
    char* wallet_cfg_path = NULL;
    char* main_cfg_path = NULL;
    char* blk_headers_path = NULL;
    char* utxo_path = NULL;
    int res = -1;

    blk_dir = kyk_asprintf("%s/blocks", wdir);
    idx_db_path = kyk_asprintf("%s/index", blk_dir);
    peers_dat_path = kyk_asprintf("%s/peers.dat", wdir);
    txdb_path = kyk_asprintf("%s/txdb", wdir);
    wallet_cfg_path = kyk_asprintf("%s/wallet.cfg", wdir);
    blk_headers_path = kyk_asprintf("%s/block_headers_chain.dat", wdir);
    main_cfg_path = kyk_asprintf("%s/main.cfg", wdir);
    utxo_path = kyk_asprintf("%s/utxo.dat", wdir);

    if(!kyk_file_exists(main_cfg_path)){
	printf("\nIt looks like you're a new user. Welcome!\n"
	       "\n"
	       "Note that kyk_miner uses the directory: %s to store:\n"
	       " - blocks:               %s/blocks                  \n"
	       " - blocks index:         %s/blocks/index            \n"
	       " - block headers chain:  %s/block_headers_chain.dat \n"
	       " - peer IP addresses:    %s/peers.dat               \n"
	       " - transaction database: %s/txdb                    \n"
	       " - wallet keys:          %s/wallet.cfg              \n"
	       " - UTXO:                 %s/utxo.dat                \n"
	       " - main config file:     %s/main.cfg              \n\n",	       
	       wdir,
	       wdir,
	       wdir,
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

    res = kyk_check_create_dir(wdir, "wallet dir");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_dir %s failed", wdir);
    wallet -> wdir = kyk_strdup(wdir);

    res = kyk_check_create_dir(blk_dir, "blocks dir");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", blk_dir);
    wallet -> blk_dir = blk_dir;

    /* res = kyk_check_create_file(idx_db_path, "blocks index path"); */
    /* check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", idx_db_path); */
    wallet -> idx_db_path = idx_db_path;

    res = kyk_check_create_file(peers_dat_path, "peers");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", peers_dat_path);
    
    res = kyk_check_create_file(txdb_path, "txdb");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", txdb_path);

    res = kyk_check_create_file(blk_headers_path, "block headers chain");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", blk_headers_path);
    wallet -> blk_hd_chain_path = blk_headers_path;
    
    res = kyk_check_create_file(wallet_cfg_path, "wallet config");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", wallet_cfg_path);
    wallet -> wallet_cfg_path = wallet_cfg_path;

    res = kyk_check_create_file(utxo_path, "UTXO");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", utxo_path);
    wallet -> utxo_path = utxo_path;
    
    res = kyk_check_create_file(main_cfg_path, "main config");
    check(res == 0, "Failed to kyk_wallet_check_config: kyk_check_create_file '%s' failed", main_cfg_path);
    

    return 0;

error:
    free(peers_dat_path);
    free(txdb_path);
    free(wallet_cfg_path);
    free(main_cfg_path);
    
    return -1;
}

int kyk_wallet_query_block_by_hashbytes(const struct kyk_wallet* wallet,
					const uint8_t* blk_hash,
					struct kyk_block** new_blk)
{
    struct kyk_block* blk = NULL;
    struct kyk_bkey_val* bval = NULL;
    char* errptr = NULL;
    int res = -1;

    check(wallet, "Failed to kyk_wallet_query_block_by_hashbytes: wallet is NULL");
    check(blk_hash, "Failed to kyk_wallet_query_block_by_hashbytes: blk_hash is NULL");

    bval = kyk_read_block(wallet -> blk_index_db, (char*)blk_hash, &errptr);
    check(errptr == NULL, "Failed to kyk_wallet_query_block_by_hashbytes: kyk_read_block failed");

    res = kyk_wallet_get_new_block_from_bval(wallet, bval, &blk);
    check(res == 0, "Failed to kyk_wallet_query_block_by_hashbytes: kyk_wallet_get_new_block_from_bval failed");

    *new_blk = blk;
    
    kyk_free_bval(bval);
    
    return 0;
    
error:

    return -1;

}

int kyk_wallet_query_block(const struct kyk_wallet* wallet,
			   const char* blk_hash,
			   struct kyk_block** new_blk)
{
    struct kyk_block* blk = NULL;
    struct kyk_bkey_val* bval = NULL;
    char* errptr = NULL;
    int res = -1;
    
    check(wallet, "Failed to kyk_wallet_query_block: wallet is NULL");
    check(blk_hash, "Failed to kyk_wallet_query_block: blk_hash is NULL");

    bval = w_get_bval(wallet, blk_hash, &errptr);
    check(errptr == NULL, "Failed to kyk_wallet_query_block: w_get_bval failed %s", errptr);

    res = kyk_wallet_get_new_block_from_bval(wallet, bval, &blk);
    check(res == 0, "Failed to kyk_wallet_query_block: kyk_wallet_get_new_block_from_bval failed");

    *new_blk = blk;

    kyk_free_bval(bval);
    
    return 0;

error:
    if(bval) kyk_free_bval(bval);
    return -1;
}


int kyk_wallet_get_new_block_from_bval(const struct kyk_wallet* wallet,
				       const struct kyk_bkey_val* bval,
				       struct kyk_block** new_blk)
{
    struct kyk_block* blk = NULL;
    char* blk_file_path = NULL;
    uint8_t buf[8];
    uint8_t* bufp = NULL;
    uint8_t* blk_buf = NULL;
    FILE* fp = NULL;
    size_t checksize = 0;
    int res = -1;
    size_t ret_code;

    check(wallet, "Failed to kyk_wallet_get_new_block_from_bval: wallet is NULL");
    check(bval, "Failed to kyk_wallet_get_new_block_from_bval: bval is NULL");

    blk = calloc(1, sizeof(*blk));
    check(blk, "Failed to kyk_wallet_get_new_block_from_bval: calloc failed");

    blk_file_path = kyk_asprintf("%s/blk%05d.dat", wallet -> blk_dir, bval -> nFile);
    fp = fopen(blk_file_path, "rb");
    check(fp, "Failed to kyk_wallet_get_new_block_from_bval: fopen failed");

    res = fseek(fp, bval -> nDataPos - 8, SEEK_SET);
    check(res == 0, "Failed to kyk_wallet_get_new_block_from_bval: fseek failed");

    bufp = buf;

    fread(bufp, sizeof(blk -> magic_no), 1, fp);
    bufp += sizeof(blk -> magic_no);

    fread(bufp, sizeof(blk -> blk_size), 1, fp);
    bufp += sizeof(blk -> blk_size);

    bufp = buf;
    beej_unpack(bufp, "<L", &blk -> magic_no);
    bufp += sizeof(blk -> magic_no);

    beej_unpack(bufp, "<L", &blk -> blk_size);

    blk_buf = calloc(blk -> blk_size, sizeof(*blk_buf));
    check(blk_buf, "Failed to kyk_wallet_get_new_block_from_bval: calloc failed");

    ret_code = fread(blk_buf, sizeof(*blk_buf), blk -> blk_size, fp);
    check(ret_code == blk -> blk_size, "Failed to kyk_wallet_get_new_block_from_bval: fread failed");

    res = kyk_deseri_block(blk, blk_buf, &checksize);
    check(res == 0, "Failed to kyk_wallet_get_new_block_from_bval: kyk_deseri_block failed");


    *new_blk = blk;
    
    fclose(fp);
    free(blk_buf);
    
    return 0;

error:
    if(fp) fclose(fp);
    if(blk_buf) free(blk_buf);
    return -1;
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
    if(wallet){
	
	if(wallet -> wdir) {
	    free(wallet -> wdir);
	    wallet -> wdir = NULL;
	}
	
	if(wallet -> blk_dir) {
	    free(wallet -> blk_dir);
	    wallet -> blk_dir = NULL;
	}
	
	if(wallet -> idx_db_path) {
	    free(wallet -> idx_db_path);
	    wallet -> idx_db_path = NULL;
	}
	
	if(wallet -> wallet_cfg_path) {
	    free(wallet -> wallet_cfg_path);
	    wallet -> wallet_cfg_path = NULL;
	}

	if(wallet -> blk_hd_chain_path){
	    free(wallet -> blk_hd_chain_path);
	    wallet -> blk_hd_chain_path = NULL;
	}
	
	
	if(wallet -> blk_index_db) {
	    kyk_free_block_db(wallet -> blk_index_db);
	    wallet -> blk_index_db = NULL;
	}

	if(wallet -> wallet_cfg){
	    kyk_config_free(wallet -> wallet_cfg);
	    wallet -> wallet_cfg = NULL;
	}

	free(wallet);
    }
}

int kyk_wallet_save_block(const struct kyk_wallet* wallet, const struct kyk_block* blk)
{
    struct kyk_blk_file* blk_file = NULL;
    struct kyk_bkey_val bval;
    int fileNo;
    char *errptr = NULL;    
    int res = -1;
    
    check(wallet, "Failed to kyk_wallet_save_block: wallet is NULL");
    check(wallet -> blk_dir, "Failed to kyk_wallet_save_block: wallet -> blk_dir is NULL");
    check(blk, "Failed to kyk_wallet_save_block: blk is NULL");

    fileNo = 0;
    blk_file = kyk_create_blk_file(fileNo, wallet -> blk_dir, "ab");
    check(blk_file, "Failed to kyk_wallet_save_block: kyk_create_blk_file failed");

    res = kyk_save_blk_to_file(blk_file, blk);
    check(res == 0, "Failed to kyk_wallet_save_block: kyk_save_blk_to_file failed");

    set_init_bval(&bval, blk, blk_file);
    kyk_store_block(wallet -> blk_index_db, &bval, &errptr);
    check(errptr == NULL, "Failed to kyk_wallet_save_block: kyk_store_block failed");
    

    kyk_close_blk_file(blk_file);
    
    return 0;

error:

    if(blk_file) kyk_close_blk_file(blk_file);
    return -1;
}

int save_setup_data_to_wallet(struct kyk_wallet *wallet)
{
    struct kyk_block *blk = NULL;
    struct kyk_bkey_val bval;
    struct kyk_blk_file* blk_file = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    int res = -1;
    char *errptr = NULL;
    
    blk = make_gens_block();
    check(blk != NULL, "failed to make gens block");

    blk_file = kyk_create_blk_file(0, wallet -> blk_dir, "ab");
    check(blk_file != NULL, "failed to create block file");

    res = kyk_save_blk_to_file(blk_file, blk);
    check(res == 0, "failed to save block to file");
    
    set_init_bval(&bval, blk, blk_file);
    kyk_store_block(wallet -> blk_index_db, &bval, &errptr);
    check(errptr == NULL, "failed to store b key value");

    res = kyk_init_blk_hd_chain(&hd_chain);
    check(res == 0, "Failed to save_setup_data_to_wallet: kyk_init_blk_hd_chain failed");

    res = kyk_append_blk_hd_chain(hd_chain, blk -> hd, 1);
    check(res == 0, "Failed to save_setup_data_to_wallet: kyk_append_blk_hd_chain failed");

    res = kyk_save_blk_header_chain(wallet, hd_chain, NULL);
    check(res == 0, "Failed to save_setup_data_to_wallet: kyk_save_blk_header_chain failed");

    kyk_free_block(blk);
    kyk_close_blk_file(blk_file);
    
    return 0;

error:
    if(blk) kyk_free_block(blk);
    if(blk_file) kyk_close_blk_file(blk_file);
    if(hd_chain) kyk_free_blk_hd_chain(hd_chain);
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
    uint8_t* buf = NULL;
    size_t blk_size = 0;
    size_t buf_len = 0;
    size_t len = 0;
    long int pos = 0;
    int res = -1;

    check(blk_file, "Failed to kyk_save_blk_to_file: blk_file is NULL");
    check(blk, "Failed to kyk_save_blk_to_file: blk is NULL");

    res = kyk_get_blkself_size(blk, &blk_size);
    check(res == 0, "Failed to kyk_save_blk_to_file: kyk_get_blk_size failed");
    check(blk_size > 0, "Failed to kyk_save_blk_to_file: blk_size is invalid");

    buf_len += blk_size;
    buf = calloc(buf_len, sizeof(*buf));
    check(buf, "Failed to kyk_save_blk_to_file: buf calloc failed");

    res = kyk_seri_blkself(buf, blk, &len);
    check(res == 0, "Failed to kyk_save_blk_to_file: kyk_seri_blkself failed");
    
    pos = ftell(blk_file -> fp);
    check(pos != -1L, "failed to get the block dat file pos");

    blk_file -> nOffsetPos = sizeof(blk -> magic_no) + sizeof(blk -> blk_size);
    
    blk_file -> nStartPos = (unsigned int)pos + blk_file -> nOffsetPos;
    
    len = fwrite(buf, sizeof(*buf), buf_len, blk_file -> fp);
    check(len == buf_len, "failed to save block to file");
    blk_file -> nEndPos = len;
    
    free(buf);
    
    return 0;
    
error:
    if(buf) free(buf);
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
    btc_addr = kyk_make_address_from_pubkey(k -> pub_key, k -> pub_len);

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
    /* check(wallet -> wallet_cfg == NULL, "wallet cfg has already been loaded"); */

    if(wallet -> wallet_cfg){
	kyk_config_free(wallet -> wallet_cfg);
	wallet -> wallet_cfg = NULL;
    }

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

int kyk_wallet_get_pubkey(uint8_t** pubkey,
			  size_t* pbk_len,
			  const struct kyk_wallet* wallet,
			  const char* name)
{
    char* pubStr = NULL;
    uint8_t* pbk_cpy = NULL;
    
    check(pubkey, "Failed to kyk_wallet_get_pubkey: pubkey is NULL");
    check(wallet, "Failed to kyk_wallet_get_pubkey: wallet is NULL");
    check(wallet -> wallet_cfg, "Failed to kyk_wallet_get_pubkey: wallet -> wallet_cfg is NULL");

    pubStr = kyk_config_getstring(wallet -> wallet_cfg, NULL, name);
    check(pubStr, "Failed to kyk_wallet_get_pubkey: pubStr is NULL");

    pbk_cpy = kyk_alloc_hex(pubStr, pbk_len);

    *pubkey = pbk_cpy;

    return 0;

error:
    if(pubStr) free(pubStr);
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

    printf("Added a new address: %s\n", k -> btc_addr);

    kyk_destroy_wallet_key(k);

    return 0;
    
error:

    kyk_destroy_wallet_key(k);
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


/* save block header chain */
int kyk_save_blk_header_chain(const struct kyk_wallet* wallet,
			      const struct kyk_blk_hd_chain* hd_chain,
			      const char* mode)
{
    FILE* fp = NULL;
    const struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_bon_buff* bbuf = NULL;
    size_t len = 0;
    int res = -1;
    

    check(wallet, "Failed to kyk_save_blk_head_chain: wallet is NULL");
    check(wallet -> blk_hd_chain_path, "Failed to kyk_save_blk_head_chain: wallet -> blk_hd_chain_path is NULL");
    check(hd_chain, "Failed to kyk_save_blk_head_chain: hd_chain is NULL");

    if(mode == NULL){
	fp = fopen(wallet -> blk_hd_chain_path, "wb");
    } else {
	fp = fopen(wallet -> blk_hd_chain_path, mode);
    }
    
    check(fp, "Failed to kyk_save_blk_head_chain: fopen failed");

    hdc = hd_chain;

    res = kyk_seri_blk_hd_chain(&bbuf, hdc);
    check(res == 0, "Failed to kyk_save_blk_head_chain: kyk_seri_blk_hd_chain failed");
    check(bbuf -> base, "Failed to kyk_save_blk_head_chain: kyk_seri_blk_hd_chain failed");

    len = fwrite(bbuf -> base, sizeof(*bbuf -> base), bbuf -> len, fp);
    check(len == bbuf -> len, "Failed to kyk_save_blk_head_chain: fwrite failed");

    free_kyk_bon_buff(bbuf);
    fclose(fp);
    
    return 0;
    
error:
    if(bbuf) free_kyk_bon_buff(bbuf);
    if(fp) fclose(fp);
    return -1;
}


int kyk_load_blk_header_chain(struct kyk_blk_hd_chain** hd_chain,
			      const struct kyk_wallet* wallet)
{
    struct kyk_blk_hd_chain* hdc = NULL;
    uint8_t* buf = NULL;
    FILE* fp = NULL;
    size_t len = 0;
    int res = -1;

    check(hd_chain, "Failed to kyk_load_blk_head_chain: hd_chain is NULL");
    check(wallet, "Failed to kyk_load_blk_head_chain: wallet is NULL");

    fp = fopen(wallet -> blk_hd_chain_path, "rb");
    check(fp, "Failed to kyk_load_blk_head_chain: fopen failed");

    res = kyk_file_read_all(&buf, fp, &len);
    check(res == 0, "Failed to kyk_load_blk_head_chain: kyk_file_read all failed");

    res = kyk_deseri_blk_hd_chain(&hdc, buf, len);
    check(res == 0, "Failed to kyk_load_blk_head_chain: kyk_deseri_blk_hd_chain failed");

    *hd_chain = hdc;
    
    fclose(fp);
    free(buf);
    
    return 0;

error:
    if(fp) fclose(fp);
    if(buf) free(buf);
    if(hdc) kyk_free_blk_hd_chain(hdc);
    return -1;
}

int kyk_load_utxo_chain_from_chainfile_buf(struct kyk_utxo_chain* utxo_chain,
					   const uint8_t* buf,
					   size_t buf_len)
{
    const uint8_t* bufp = NULL;
    uint32_t chain_len = 0;
    size_t check_num = 0;
    int res = -1;
    
    check(utxo_chain, "Failed to kyk_load_utxo_chain_from_buf: utxo_chain is NULL");
    check(utxo_chain -> hd == NULL, "Failed to kyk_load_utxo_chain_from_buf: utxo_chain -> hd should be NULL");
    check(buf, "Failed to kyk_load_utxo_chain_from_buf: buf is NULL");

    bufp = buf;

    beej_unpack(bufp, "<L", &chain_len);
    bufp += sizeof(chain_len);

    res = kyk_deseri_utxo_chain(utxo_chain, bufp, chain_len, &check_num);
    check(res == 0, "Failed to kyk_load_utxo_chain: kyk_deseri_utxo_chain failed");
    if(buf_len > 0){
	check(check_num <= buf_len, "Failed to kyk_load_utxo_chain: kyk_deseri_utxo_chain failed");
    }
    

    return 0;

error:

    return -1;

}

int kyk_load_utxo_chain(struct kyk_utxo_chain** new_utxo_chain,
			const struct kyk_wallet* wallet)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    uint8_t* buf = NULL;
    FILE* fp = NULL;
    int res = -1;

    check(new_utxo_chain, "Failed to kyk_load_utxo_chain: utxo_chain is NULL");
    check(wallet, "Failed to kyk_load_utxo_chain: wallet is NULL");

    fp = fopen(wallet -> utxo_path, "rb");
    check(fp, "Failed to kyk_load_utxo_chain: fopen failed");

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    check(utxo_chain, "Failed to kyk_deseri_utxo_chain: utxo_chain calloc failed");
    kyk_init_utxo_chain(utxo_chain);


    res = kyk_file_read_all(&buf, fp, NULL);
    check(res == 0, "Failed to kyk_load_utxo_chain: kyk_file_read_all failed");

    if(buf){
	res = kyk_load_utxo_chain_from_chainfile_buf(utxo_chain, buf, 0);
    	check(res == 0, "Failed to kyk_load_utxo_chain: kyk_load_utxo_chain_from_chainfile_buf failed");
    }

    *new_utxo_chain = utxo_chain;

    if(fp) fclose(fp);
    if(buf) free(buf);

    return 0;
    
error:
    if(fp) fclose(fp);
    if(buf) free(buf);
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return -1;
}

int kyk_wallet_save_utxo_chain(const struct kyk_wallet* wallet, const struct kyk_utxo_chain* utxo_chain)
{
    FILE* fp = NULL;
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    size_t buf_size = 0;
    size_t chain_size = 0;
    size_t len = 0;
    int res = -1;

    check(wallet, "Failed to kyk_wallet_save_utxo_chain: wallet is NULL");
    check(wallet -> utxo_path, "Failed to kyk_wallet_save_utxo_chain: wallet -> utxo_path is NULL");
    check(utxo_chain, "Failed to kyk_wallet_save_utxo_chain: utxo_chain is NULL");

    fp = fopen(wallet -> utxo_path, "wb");
    check(fp, "Failed to kyk_wallet_save_utxo_chain: fopen %s failed", wallet -> utxo_path);

    res = kyk_get_utxo_chain_size(utxo_chain, &buf_size);
    check(res == 0, "Failed to kyk_wallet_save_utxo_chain: kyk_get_utxo_chain_size failed");

    buf_size += sizeof(utxo_chain -> len);
    buf = calloc(buf_size, sizeof(*buf));
    check(buf, "Failed to kyk_wallet_save_utxo_chain: buf calloc failed");

    bufp = buf;

    beej_pack(bufp, "<L", utxo_chain -> len);
    bufp += sizeof(utxo_chain -> len);
    
    res = kyk_seri_utxo_chain(bufp, utxo_chain, &chain_size);
    check(res == 0, "Failed to kyk_wallet_save_utxo_chain: kyk_seri_utxo_chain failed");
    /* check(chain_size == buf_size - sizeof(utxo_chain -> len), "Failed to kyk_wallet_save_utxo_chain: kyk_seri_utxo_chain failed"); */

    len = fwrite(buf, sizeof(*buf), buf_size, fp);
    check(len == buf_size, "Failed to kyk_wallet_save_utxo_chain: fwrite failed");

    free(buf);
    fclose(fp);
	
    return 0;
    
error:
    if(buf) free(buf);
    if(fp) fclose(fp);
    return -1;
}

int kyk_wallet_query_total_balance(const struct kyk_wallet* wallet, uint64_t* balance)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    char** addr_list = NULL;
    char* addr = NULL;
    size_t addr_list_len = 0;
    uint64_t value = 0;
    uint64_t total_value = 0;
    size_t i = 0;
    int res = -1;
    
    check(wallet, "Failed to kyk_wallet_query_total_balance: wallet is NULL");

    res = kyk_load_utxo_chain(&utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_query_total_balance: kyk_load_utxo_chain failed");

    res = kyk_wallet_load_addr_list(wallet, &addr_list, &addr_list_len);
    check(res == 0, "Failed to kyk_wallet_query_total_balance: kyk_wallet_load_addr_list failed");

    for(i = 0; i < addr_list_len; i++){
	addr = addr_list[i];
	res = kyk_wallet_query_value_by_addr(addr, utxo_chain, &value);
	check(res == 0, "Failed to kyk_wallet_query_total_balance: kyk_wallet_query_value_by_addr failed");
	total_value += value;
    }

    *balance = total_value;

    free_addr_list(addr_list, addr_list_len);
    kyk_free_utxo_chain(utxo_chain);

    return 0;

error:
    if(addr_list) free_addr_list(addr_list, addr_list_len);
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    
    return -1;
}

void free_addr_list(char** addr_list, size_t len)
{
    size_t i = 0;
    
    if(addr_list){
	for(i = 0; i < len; i++){
	    if(addr_list[i]){
		free(addr_list[i]);
	    }
	}

	free(addr_list);
    }
}

int kyk_wallet_query_value_by_addr(const char* btc_addr,
				   const struct kyk_utxo_chain* utxo_chain,
				   uint64_t* value)
{
    struct kyk_utxo* utxo = NULL;
    uint64_t utxo_value = 0;

    check(btc_addr, "Failed to kyk_wallet_query_value_by_addr: btc_addr is NULL");
    check(utxo_chain, "Failed to kyk_wallet_query_value_by_addr: utxo_chain is NULL");

    utxo = utxo_chain -> hd;
    while(utxo){
	if(kyk_utxo_match_addr(utxo, btc_addr) == 0 && utxo -> spent == 0){
	    utxo_value += utxo -> value;
	}
	utxo = utxo -> next;
    }

    *value = utxo_value;

    return 0;
    
error:

    return -1;
}

int kyk_wallet_load_addr_list(const struct kyk_wallet* wallet,
			      char** new_addr_list[],
			      size_t* nlen)
{
    const struct config* cfg;
    struct KeyValuePair* ev = NULL;
    char** addr_list = NULL;
    char** addr = NULL;
    size_t len = 0;
    size_t i = 0;
    int res = -1;

    check(wallet, "Failed to kyk_wallet_load_addr_list: wallet is NULL");
    check(wallet -> wallet_cfg, "Failed to kyk_wallet_load_addr_list: wallet -> wallet_cfg is NULL");
    check(new_addr_list, "Failed to kyk_wallet_load_addr_list: new_addr_list is NULL");
    check(nlen, "Failed to kyk_wallet_load_addr_list: len is NULL");

    cfg = wallet -> wallet_cfg;

    res = kyk_config_get_item_count(cfg, "pubkey", &len);
    check(res == 0, "Failed to kyk_wallet_load_addr_list: kyk_config_get_item_count failed");

    if(len == 0) return 0;

    addr_list = calloc(len, sizeof(*addr_list));
    check(addr_list, "Failed to kyk_wallet_load_addr_list: addr_list calloc failed");
    
    ev = cfg -> list;
    i = 0;
    
    while(ev && i < len){
	if(strstr(ev -> key, "pubkey")){
	    addr = addr_list + i;
	    res = get_address(ev, addr);
	    check(res == 0, "Failed to kyk_wallet_load_addr_list: get_address failed");
	    i++;
	}
	ev = ev -> next;
    }

    *new_addr_list = addr_list;
    *nlen = len;

    return 0;

error:
    if(addr_list){
	for(i = 0; i < len; i++){
	    addr = addr_list + i;
	    if(*addr) free(*addr);
	}
	free(addr_list);
    }
    return -1;
}

int get_address(const struct KeyValuePair* ev, char** new_addr)
{
    uint8_t* pubkey = NULL;
    size_t pbk_len = 0;
    char* addr = NULL;
    
    check(ev, "Failed to get_address: ev is NULL");
    check(new_addr, "Failed to get_address: new_addr is NULL");
    check(strstr(ev -> key, "pubkey"), "Failed to get_address: ev is not pubkey");

    pubkey = kyk_alloc_hex(ev -> u.str, &pbk_len);
    check(pbk_len > 0, "Failed to get_address: kyk_alloc_hex failed");

    addr = kyk_make_address_from_pubkey(pubkey, pbk_len);
    check(addr, "Failed to get_address: kyk_make_address_from_pubkey failed");

    *new_addr = addr;

    free(pubkey);

    return 0;
    
error:
    if(pubkey) free(pubkey);
    return -1;
}

int kyk_wallet_make_tx(struct kyk_tx** new_tx,
		       struct kyk_utxo_chain** new_utxo_chain,
		       uint32_t version,
		       struct kyk_wallet* wallet,		       
		       struct kyk_utxo_chain* wallet_utxo_chain,
		       uint64_t value,
		       const char* btc_addr)
{
    struct kyk_tx* tx = NULL;
    struct kyk_utxo_chain* value_utxo_chain = NULL;
    /* struct kyk_utxo_chain* wallet_utxo_chain = NULL; */
    struct kyk_wkey_chain* wkey_chain = NULL;
    const char* mc_addr = NULL;
    uint64_t amount = 0;
    uint64_t mfee = 0;
    int res = -1;
    
    check(new_tx, "Failed to kyk_wallet_make_tx: new_tx is NULL");
    check(wallet, "Failed to kyk_wallet_make_tx: wallet is NULL");
    check(wallet_utxo_chain, "Failed to kyk_wallet_make_tx: wallet_utxo_chain is NULL");
    /* check(new_utxo_chain, "Failed to kyk_wallet_make_tx: new_utxo_chain is NULL"); */
    check(value > 0, "Failed to kyk_wallet_makx_tx: value should greater than zero");
    check(value < TOTAL_BTC_VALUE, "Failed to kyk_wallet_makx_tx: value should be less than TOTAL_BTC_VALUE");
    check(btc_addr, "Failed to kyk_wallet_make_tx: btc_addr is NULL");

    amount = value;
    mfee = KYK_MINER_FEE;

    res = kyk_validate_address(btc_addr, strlen(btc_addr));
    check(res == 0, "Failed to kyk_wallet_make_tx: kyk_validate_address failed");

    res = kyk_find_available_utxo_list(&value_utxo_chain, wallet_utxo_chain, amount + mfee);
    check(res == 0, "Failed to kyk_wallet_make_tx: kyk_find_available_utxo_list failed");
    check(value_utxo_chain -> hd, "Failed to kyk_wallet_make_tx: kyk_find_available_utxo_list failed");


    res = kyk_wallet_load_key_list(wallet, &wkey_chain);
    check(res == 0, "Failed to kyk_wallet_make_tx: kyk_wallet_load_key_list failed");
    check(wkey_chain -> hd, "Failed to kyk_wallet_make_tx: kyk_wallet_load_key_list failed");

    mc_addr = wkey_chain -> hd -> addr;
    res = kyk_wallet_make_tx_from_utxo_chain(&tx, amount, mfee, btc_addr, mc_addr, version, value_utxo_chain, wkey_chain);
    check(res == 0, "Failed to kyk_wallet_make_tx: kyk_wallet_make_tx_from_utxo_chain failed");

    *new_tx = tx;

    if(new_utxo_chain){
	*new_utxo_chain = value_utxo_chain;
    }

    kyk_wkey_chain_free(wkey_chain);
    
    return 0;

error:
    if(value_utxo_chain) kyk_free_utxo_chain(value_utxo_chain);
    if(wkey_chain) kyk_wkey_chain_free(wkey_chain);
    return -1;
}


int kyk_wallet_load_key_list(struct kyk_wallet* wallet, struct kyk_wkey_chain** new_wkey_chain)
{
    struct config* cfg = NULL;
    struct kyk_wkey_chain* wkey_chain = NULL;
    struct kyk_wkey* wkey = NULL;
    int cfg_idx = 0;
    int i = 0;
    int res = -1;
    
    check(wallet, "Failed to kyk_wallet_load_key_list: wallet is NULL");
    
    if(wallet -> wallet_cfg == NULL || wallet -> wallet_cfg -> list == NULL){
	res = kyk_load_wallet_cfg(wallet);
	check(res == 0, "failed to kyk_load_wallet_cfg");	
    }

    res = kyk_wallet_get_cfg_idx(wallet, &cfg_idx);
    check(res == 0, "Failed to kyk_wallet_load_key_list: kyk_wallet_get_cfg_idx failed");

    wkey_chain = calloc(1, sizeof(*wkey_chain));
    check(wkey_chain, "Failed to kyk_wallet_load_key_list: wkey_chain calloc failed");    

    cfg = wallet -> wallet_cfg;
    
    for(i = 0; i < cfg_idx; i++){
	char* priv_str = NULL;
	char* pub_str = NULL;
	
	wkey = calloc(1, sizeof(*wkey));
	check(wkey, "Failed to kyk_wallet_load_key_list: wkey calloc failed");
	
	wkey -> addr = kyk_config_getstring(cfg, NULL, "key%u.address", i);
	if(wkey -> addr == NULL){
	    continue;
	}

	priv_str = kyk_config_getstring(cfg, NULL, "key%u.privkey", i);
	check(priv_str, "Failed to kyk_wallet_load_key_list: priv_str kyk_config_getstring failed");

	res = kyk_base58_decode_check(priv_str, strlen(priv_str), &wkey -> priv, &wkey -> priv_len);
	check(res == 0, "Failed to kyk_wallet_load_key_list: kyk_base58_decode_check failed");

	pub_str = kyk_config_getstring(cfg, NULL, "key%u.pubkey", i);
	check(pub_str, "Failed to kyk_wallet_load_key_list: pub_str kyk_config_getstring failed");

	wkey -> pub = kyk_alloc_hex(pub_str, &wkey -> pub_len);

	res = kyk_wkey_chain_append_wkey(wkey_chain, wkey);
	check(res == 0, "Failed to kyk_wallet_load_key_list: kyk_wkey_chain_append_wkey failed");

    }

    *new_wkey_chain = wkey_chain;

    return 0;

error:
    if(wkey_chain) kyk_wkey_chain_free(wkey_chain);
    return -1;

}

void kyk_print_wkey_chain(const struct kyk_wkey_chain* wkey_chain)
{
    struct kyk_wkey* wkey = NULL;

    wkey = wkey_chain -> hd;
    while(wkey){
	kyk_print_wkey(wkey);
	printf("\n\n");
	wkey = wkey -> next;
    }
}

void kyk_print_wkey(const struct kyk_wkey* wkey)
{
    printf("wkey -> addr: %s\n", wkey -> addr);
    kyk_print_hex("wkey -> priv ", wkey -> priv, wkey -> priv_len);
    kyk_print_hex("wkey -> pub ", wkey -> pub, wkey -> pub_len);
}

void kyk_wkey_chain_free(struct kyk_wkey_chain* wkey_chain)
{
    struct kyk_wkey* wkey = NULL;
    struct kyk_wkey* wkey_next = NULL;
    
    if(wkey_chain){
	wkey = wkey_chain -> hd;
	while(wkey){
	    wkey_next = wkey -> next;
	    kyk_wkey_free(wkey);
	    wkey = wkey_next;
	}

	free(wkey_chain);
    }
}

void kyk_wkey_free(struct kyk_wkey* wkey)
{
    if(wkey){
	
	if(wkey -> addr){
	    free(wkey -> addr);
	    wkey -> addr = NULL;
	}
	
	if(wkey -> priv){
	    free(wkey -> priv);
	    wkey -> priv = NULL;
	}

	if(wkey -> pub){
	    free(wkey -> pub);
	    wkey -> pub = NULL;
	}

	free(wkey);
    }
}

int kyk_wkey_chain_append_wkey(struct kyk_wkey_chain* wkey_chain,
			       struct kyk_wkey* wkey)
{
    check(wkey_chain, "Failed to kyk_wkey_chain_append_wkey: wkey_chain is failed");
    check(wkey, "Failed to kyk_wkey_chain_append_wkey: wkey is NULL");
    check(wkey -> next == NULL, "Failed to kyk_wkey_chain_append_wkey: wkey -> next should be NULL");

    if(wkey_chain -> hd == NULL){
	wkey_chain -> hd = wkey;
	wkey_chain -> tail = wkey;
	wkey_chain -> len = 1;
    } else {
	wkey_chain -> tail -> next = wkey;
	wkey_chain -> tail = wkey;
	wkey_chain -> len += 1;
    }

    return 0;

error:
    return -1;
}



int kyk_wallet_make_tx_from_utxo_chain(struct kyk_tx** new_tx,
				       uint64_t amount,         /* amount excluded miner fee        */
				       uint64_t mfee,           /* miner fee                        */
				       const char* to_addr,     /* send btc amount to this address  */
				       const char* mc_addr,     /* make change back to this address */
				       uint32_t version,
				       const struct kyk_utxo_chain* utxo_chain,
				       const struct kyk_wkey_chain* wkey_chain)
{
    struct kyk_tx* tx = NULL;
    struct kyk_utxo* utxo = NULL;
    struct kyk_txin* txin_list = NULL;
    struct kyk_txout* txout_list = NULL;
    struct kyk_txout* txout = NULL;
    size_t txout_count = 0;
    size_t i = 0;
    varint_t txin_count = 0;
    uint64_t total_value = 0;
    uint64_t back_charge = 0;
    int res = -1;

    check(new_tx, "Failed to kyk_make_tx_from_utxo_chain: new_tx is NULL");
    check(utxo_chain, "Failed to kyk_make_tx_from_utxo_chain: utxo_chain is NULL");
    check(utxo_chain -> len > 0, "Failed to kyk_make_tx_from_utxo_chain: utxo_chain -> len should be > 0");

    tx = calloc(1, sizeof(*tx));
    check(tx, "Failed to kyk_make_tx_from_utxo_chain: tx calloc failed");    

    utxo = utxo_chain -> hd;
    
    /* Unlock UTXO, in this time didn't make signature */
    res = kyk_unlock_utxo_chain(utxo_chain, &txin_list, &txin_count);
    check(res == 0, "Failed to kyk_make_tx_from_utxo_chain: kyk_unlock_utxo_chain failed");

    res = kyk_utxo_chain_get_total_value(utxo_chain, &total_value);
    check(res == 0, "Failed to kyk_make_tx_from_utxo_chain: kyk_utxo_chain_get_total_value failed");
    check(total_value >= amount + mfee, "Failed to kyk_make_tx_from_utxo_chain: total_value is invalid");

    /* txout for amount */
    txout_count += 1;
    
    back_charge = total_value - (amount + mfee);
    if(back_charge > 0){
	/* txout for charge back */
	txout_count += 1;
    }

    txout_list = calloc(txout_count, sizeof(*txout_list));
    check(txout_list, "Failed to kyk_make_tx_from_utxo_chain: txout_list calloc failed");

    txout = txout_list;
    res = kyk_make_p2pkh_txout(txout, to_addr, strlen(to_addr), amount);
    check(res == 0, "Failed to kyk_make_tx_from_utxo_chain: kyk_make_p2pkh_txout failed");
    i++;

    if(i < txout_count){
	txout = txout_list + 1;
	res = kyk_make_p2pkh_txout(txout, mc_addr, strlen(mc_addr), back_charge);
	check(res == 0, "Failed to kyk_make_tx_from_utxo_chain: kyk_make_p2pkh_txout failed");
	i++;
    }

    /* unsigned TX */
    tx -> version = version;
    tx -> vin_sz = txin_count;
    tx -> txin = txin_list;
    tx -> vout_sz = txout_count;
    tx -> txout = txout_list;
    tx -> lock_time = MORMALLY_TX_LOCK_TIME;

    /* make signature to TX */
    res = kyk_wallet_do_sign_tx(tx, utxo_chain, wkey_chain);
    check(res == 0, "Faield to kyk_wallet_make_tx_from_utxo_chain: kyk_wallet_do_sign_tx failed");

    *new_tx = tx;

    return 0;
    
error:
    if(tx) kyk_free_tx(tx);
    return -1;
}


int kyk_wallet_do_sign_tx(const struct kyk_tx* tx,
			  const struct kyk_utxo_chain* utxo_chain,
			  const struct kyk_wkey_chain* wkey_chain)
{
    struct kyk_txin* txin = NULL;
    struct kyk_utxo* utxo = NULL;
    struct kyk_txout* txout = NULL;
    struct kyk_wkey* wkey = NULL;
    uint8_t* buf = NULL;
    size_t buf_len = 0;
    uint8_t* der_buf = NULL;
    size_t der_buf_len = 0;
    varint_t i = 0;
    int res = -1;
    uint32_t htype = HTYPE_SIGHASH_ALL;
    
    check(tx, "Failed to kyk_wallet_do_sign_tx: tx is NULL");
    check(utxo_chain, "Failed to kyk_wallet_do_sign_tx: utxo_chain is NULL");

    for(i = 0; i < tx -> vin_sz; i++){
	
	txin = tx -> txin + i;
	
	utxo = kyk_find_utxo_with_txin(utxo_chain, txin);
	check(utxo, "Failed to kyk_wallet_do_sign_tx: kyk_find_utxo_with_txin failed");
	
	res = kyk_copy_new_txout_from_utxo(&txout, utxo);
	check(res == 0, "Failed to kyk_wallet_do_sign_tx: kyk_copy_new_txout_from_utxo failed");
	
	res = kyk_seri_tx_for_sig(tx, htype, i, txout, &buf, &buf_len); 
	check(res == 0, "Failed to kyk_wallet_do_sign_tx: kyk_seri_tx_for_sig failed");

	wkey = kyk_find_wkey_by_addr(wkey_chain, utxo -> btc_addr);
	check(wkey, "Failed to kyk_wallet_do_sign_tx: kyk_find_wkey_by_addr failed");

	res = kyk_ec_sign_hash256(wkey -> priv, buf, buf_len, &der_buf, &der_buf_len);

	res = kyk_set_txin_script_sig(txin, der_buf, der_buf_len, wkey -> pub, wkey -> pub_len, htype);
	check(res == 0, "Failed to kyk_wallet_do_sign_tx: kyk_set_txin_script_sig failed");

	kyk_free_txout(txout);
	free(buf);
    }


    return 0;
    
error:
    if(txout) kyk_free_txout(txout);
    if(buf) free(buf);
    return -1;
}

struct kyk_wkey* kyk_find_wkey_by_addr(const struct kyk_wkey_chain* wkey_chain, const char* addr)
{
    struct kyk_wkey* wkey = NULL;

    check(wkey_chain, "Failed to kyk_find_wkey_by_addr: wkey_chain is NULL");
    check(addr, "Failed to kyk_find_wkey_by_addr: addr is NULL");

    wkey = wkey_chain -> hd;
    while(wkey){
	if(strcmp(addr, wkey -> addr) == 0){
	    return wkey;
	}
	wkey = wkey -> next;
    }

    return NULL;

error:

    return NULL;
}


int kyk_wallet_make_coinbase_block(struct kyk_block** new_blk, const struct kyk_wallet* wallet)
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    const char* note = "void coin";
    uint8_t* pubkey = NULL;
    size_t pbk_len = 0;
    struct kyk_block* blk = NULL;
    struct kyk_utxo_chain* utxo_chain = NULL;
    int res = -1;
    uint8_t digest[32];

    res = kyk_wallet_get_pubkey(&pubkey, &pbk_len, wallet, "key0.pubkey");
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_wallet_get_pubkey failed");

    res = kyk_load_blk_header_chain(&hd_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_load_blk_header_chain failed");

    res = kyk_make_coinbase_block(&blk, hd_chain, note, pubkey, pbk_len);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_make_conibase_block failed");

    res = kyk_validate_block(hd_chain, blk);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_validate_block failed");

    res = kyk_append_blk_hd_chain(hd_chain, blk -> hd, 1);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_append_blk_hd_chain failed");

    res = kyk_load_utxo_chain(&utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_load_utxo_chain failed");

    res = kyk_append_utxo_chain_from_block(utxo_chain, blk);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_append_utxo_chain_from_block failed");

    res = kyk_wallet_save_utxo_chain(wallet, utxo_chain);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_wallet_save_utxo_chain failed");

    res = kyk_save_blk_header_chain(wallet, hd_chain, NULL);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_save_blk_header_chain failed");

    res = kyk_wallet_save_block(wallet, blk);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_wallet_save_block failed");

    kyk_blk_hash256(digest, blk -> hd);
    kyk_print_hex("maked a new block", digest, sizeof(digest));

    if(new_blk){
	*new_blk = blk;
    } else {
	kyk_free_block(blk);
    }

    free(pubkey);
    kyk_free_utxo_chain(utxo_chain);
    
    return 0;

error:
    if(pubkey) free(pubkey);
    if(blk) kyk_free_block(blk);
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return -1;

}

int kyk_wallet_update_utxo_chain_with_block_list(const struct kyk_wallet* wallet,
						 const struct kyk_block_list* blk_list)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    struct kyk_utxo_chain* utxo_chain1 = NULL;
    struct kyk_utxo_chain* newly_utxo_chain = NULL;
    struct kyk_block* blk = NULL;
    size_t i = 0;
    int res = -1;

    res = kyk_load_utxo_chain(&utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_load_utxo_chain failed");

    for(i = 0; i < blk_list -> len; i++){
	blk = blk_list -> data + i;
	res = kyk_append_utxo_chain_from_block(utxo_chain, blk);
	check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_append_utxo_chain_from_block failed");
    }

    for(i = 0; i < blk_list -> len; i++){
	blk = blk_list -> data + i;
	res = kyk_set_spent_utxo_within_block(utxo_chain, blk);
	check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_set_spent_utxo failed");
    }

    res = kyk_remove_spent_utxo(&utxo_chain1, utxo_chain);
    check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_remove_spent_utxo failed");

    kyk_print_utxo_chain(utxo_chain);

    res = kyk_remove_repeated_utxo(&newly_utxo_chain, utxo_chain1);
    check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_remove_repeated_utxo failed");

    res = kyk_wallet_save_utxo_chain(wallet, newly_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_update_utxo_chain_with_block_list: kyk_wallet_save_utxo_chain failed");

    kyk_free_utxo_chain(utxo_chain);
    return 0;
    
error:
    
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return -1;
    
}

int kyk_wallet_cmd_make_tx( struct kyk_block** new_blk,
			    struct kyk_wallet* wallet,
			    long double btc_num,
			    const char* btc_addr)
{
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* updated_utxo_chain = NULL;
    struct kyk_utxo_chain* tx_utxo_chain = NULL;
    struct kyk_block* blk = NULL;
    struct kyk_tx* tx = NULL;
    uint8_t* pubkey = NULL;
    size_t pub_len = 0;
    uint32_t version = 1;
    uint64_t value = 0;
    uint64_t total_value = 0;
    uint64_t mfee = 0;
    int res = -1;

    check(wallet, "Failed to kyk_wallet_cmd_make_tx: wallet is NULL");
    check(btc_num > 0, "Failed to kyk_wallet_cmd_make_tx: btc_num is invalid");
    check(btc_addr, "Failed to kyk_wallet_cmd_make_tx: btc_addr is NULL");

    value = btc_num * ONE_BTC_COIN_VALUE;

    res = kyk_wallet_query_total_balance(wallet, &total_value);
    check(res == 0, "Fialed to kyk_wallet_cmd_make_tx: kyk_wallet_query_total_balance failed");
    check(total_value >= value, "Failed to kyk_wallet_cmd_make_tx: not sufficient funds");

    res = kyk_wallet_get_pubkey(&pubkey, &pub_len, wallet, KYK_DEFAULT_PUBKEY_NAME);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_get_pubkey failed");

    res = kyk_load_blk_header_chain(&hd_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_blk_header_chain failed");

    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_utxo_chain failed");    

    res = kyk_wallet_make_tx(&tx, &tx_utxo_chain, version, wallet, wallet_utxo_chain, value, btc_addr);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_make_tx failed");
    check(tx_utxo_chain, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_make_tx failed");
    check(tx_utxo_chain -> len > 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_make_tx failed");

    res = kyk_wallet_get_mfee(tx, tx_utxo_chain, &mfee);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_get_mfee failed");

    res = kyk_make_tx_block(&blk, hd_chain, tx, mfee, 1, KYK_DEFAULT_NOTE, pubkey, pub_len);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_make_tx_block failed");

    res = kyk_validate_block(hd_chain, blk);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_validate_block failed");

    res = kyk_append_blk_hd_chain(hd_chain, blk -> hd, 1);
    check(res == 0, "Failed to kyk_wallet_make_coinbase_block: kyk_append_blk_hd_chain failed");

    res = kyk_append_utxo_chain_from_block(wallet_utxo_chain, blk);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_append_utxo_chain_from_block failed");

    kyk_wallet_set_utxo_chain_spent(tx_utxo_chain);

    res = kyk_remove_spent_utxo(&updated_utxo_chain, wallet_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_remove_spent_utxo failed");

    kyk_print_utxo_chain(updated_utxo_chain);

    res = kyk_wallet_save_utxo_chain(wallet, updated_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_save_utxo_chain failed");

    res = kyk_save_blk_header_chain(wallet, hd_chain, NULL);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_save_blk_header_chain failed");

    res = kyk_wallet_save_block(wallet, blk);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_wallet_save_block failed");

    if(new_blk){
	*new_blk = blk;
    } else {
	kyk_free_block(blk);
    }

    free(pubkey);
    kyk_free_utxo_chain(tx_utxo_chain);
    kyk_free_utxo_chain(wallet_utxo_chain);
    free(updated_utxo_chain);

    return 0;

error:
    if(pubkey) free(pubkey);
    if(blk) kyk_free_block(blk);

    if(tx_utxo_chain) kyk_free_utxo_chain(tx_utxo_chain);
    if(wallet_utxo_chain) kyk_free_utxo_chain(wallet_utxo_chain);
    if(updated_utxo_chain) free(updated_utxo_chain);
    

    return -1;

}


int kyk_wallet_get_mfee(const struct kyk_tx* tx,
			const struct kyk_utxo_chain* utxo_chain,
			uint64_t* mfee)
{
    uint64_t output_value = 0;
    uint64_t txout_value = 0;
    int res = -1;
    
    check(tx, "Failed to kyk_wallet_get_mfee: tx is NULL");
    check(utxo_chain, "Failed to kyk_wallet_get_mfee: utxo_chain is NULL");

    res = kyk_get_total_utxo_value(utxo_chain, &output_value);
    check(res == 0, "Failed to kyk_wallet_get_mfee: kyk_get_total_utxo_value failed");

    res = kyk_get_total_txout_value(tx, &txout_value);
    check(res == 0, "Failed to kyk_wallet_get_mfee: kyk_get_total_txout_value failed");
    check(output_value >= txout_value, "Failed to kyk_wallet_get_mfee: mfee should be >= 0");

    *mfee = output_value - txout_value;
    
    return 0;
    
error:

    return -1;
}


int kyk_wallet_set_utxo_chain_spent(struct kyk_utxo_chain* utxo_chain)
{
    struct kyk_utxo* utxo = NULL;
    size_t i = 0;
    check(utxo_chain, "Failed to kyk_wallet_set_utxo_chain_spent: utxo_chain is NULL");

    utxo = utxo_chain -> hd;
    while(utxo && i < utxo_chain -> len){
	utxo -> spent = 1;
	if(utxo -> refer_to){
	    utxo -> refer_to -> spent = 1;
	}
	utxo = utxo -> next;
	i++;
    }

    return 0;

error:

    return -1;
}


int kyk_spv_wallet_make_tx(struct kyk_tx** new_tx,
			   struct kyk_wallet* wallet,
			   long double btc_num,
			   const char* btc_addr)
{
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* filtered_utxo_chain = NULL;
    struct kyk_tx* tx = NULL;
    uint32_t version = 1;
    uint64_t value = 0;
    uint64_t total_value = 0;
    int res = -1;

    check(wallet, "Failed to kyk_spv_wallet_make_tx: wallet is NULL");
    check(btc_num > 0, "Failed to kyk_spv_wallet__make_tx: btc_num is invalid");
    check(btc_addr, "Failed to kyk_spv_wallet_make_tx: btc_addr is NULL");

    value = btc_num * ONE_BTC_COIN_VALUE;

    res = kyk_wallet_query_total_balance(wallet, &total_value);
    check(res == 0, "Fialed to kyk_spv_wallet_make_tx: kyk_wallet_query_total_balance failed");
    check(total_value >= value, "Failed to kyk_spv_wallet_make_tx: not sufficient funds");

    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_cmd_make_tx: kyk_load_utxo_chain failed");

    res = kyk_wallet_filter_utxo_chain(&filtered_utxo_chain, wallet_utxo_chain, wallet);

    res = kyk_wallet_make_tx(&tx, NULL, version, wallet, filtered_utxo_chain, value, btc_addr);
    check(res == 0, "Failed to kyk_spv_wallet_make_tx: kyk_wallet_make_tx failed");

    *new_tx = tx;

    return 0;

error:

    return -1;

}


int kyk_wallet_filter_utxo_chain(struct kyk_utxo_chain** new_utxo_chain,
				 struct kyk_utxo_chain* src_utxo_chain,
				 const struct kyk_wallet* wallet)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    char** addr_list = NULL;
    size_t len = 0;
    size_t i = 0;
    int res = -1;

    check(new_utxo_chain, "Failed to kyk_wallet_filter_utxo_chain: new_utxo_chain is NULL");
    check(src_utxo_chain, "Failed to kyk_wallet_filter_utxo_chain: src_utxo_chain is NULL");
    check(wallet, "Failed to kyk_wallet_filter_utxo_chain: wallet is NULL");

    utxo_chain = calloc(1, sizeof(*utxo_chain));
    check(utxo_chain, "Failed to kyk_wallet_filter_utxo_chain: calloc failed");

    res = kyk_wallet_load_addr_list(wallet, &addr_list, &len);
    check(res == 0, "Failed to kyk_wallet_filter_utxo_chain: kyk_wallet_load_addr_list failed");

    for(i = 0; i < len; i++){
	res = kyk_filter_utxo_chain_by_addr(utxo_chain, src_utxo_chain, addr_list[i]);
	check(res == 0, "Failed to kyk_wallet_filter_utxo_chain: kyk_filter_utxo_chain_by_addr failed");
    }

    *new_utxo_chain = utxo_chain;

    return 0;
    
error:
    if(utxo_chain) kyk_free_utxo_chain(utxo_chain);
    return -1;
}


int kyk_wallet_find_utxo_list_for_tx(const struct kyk_wallet* wallet,
				     const struct kyk_tx* tx,
				     struct kyk_utxo_list* utxo_list)
{
    struct kyk_utxo* utxo = NULL;
    struct kyk_utxo* dest_utxo = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    size_t i = 0;
    size_t j = 0;
    
    int res = -1;
    
    check(wallet, "Failed to kyk_wallet_find_utxo_list_for_tx: wallet is NULL");
    check(tx, "Failed to kyk_wallet_find_utxo_list_for_tx: tx is NULL");
    check(tx -> vin_sz > 0, "Failed to kyk_wallet_find_utxo_list_for_tx: tx -> vin_sz is invalid");
    check(utxo_list, "Failed to kyk_wallet_find_utxo_list_for_tx: utxo_list is NULL");
    check(utxo_list -> data == NULL, "Failed to kyk_wallet_find_utxo_list_for_tx: utxo_list -> data should be NULL");

    utxo_list -> len = 0;

    utxo_list -> data = calloc(tx -> vin_sz, sizeof(*utxo_list -> data));
    check(utxo_list -> data, "Failed to kyk_wallet_find_utxo_list_for_tx: calloc failed");

    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_find_utxo_list_for_tx: kyk_load_utxo_chain failed");

    for(i = 0; i < tx -> vin_sz; i++){
	utxo = wallet_utxo_chain -> hd;
	for(j = 0; j < wallet_utxo_chain -> len; j++){
	    /* kyk_print_utxo(utxo); */
	    res = kyk_utxo_match_txin(utxo, tx -> txin + i);
	    if(res == 0){
		dest_utxo = utxo_list -> data + i;
		kyk_copy_utxo(dest_utxo, utxo);
		utxo_list -> len += 1;
		break;
	    }
	    utxo = utxo -> next;
	}

	/* didn't find matched utxo for txin */
	check(utxo_list -> len == i+1, "Failed to kyk_wallet_find_utxo_list_for_tx: no matched utxo for txin: %zu", i);
    }
    
    return 0;
    
error:
    if(utxo_list -> data) free(utxo_list -> data);
    return -1;
}


int kyk_wallet_mining_block(struct kyk_block** new_blk,
			    const struct kyk_tx* tx,
			    struct kyk_utxo_list* utxo_list,
			    struct kyk_wallet* wallet)
{
    struct kyk_block* blk = NULL;
    struct kyk_blk_hd_chain* hd_chain = NULL;
    struct kyk_utxo_chain* wallet_utxo_chain = NULL;
    struct kyk_utxo_chain* tx_utxo_chain = NULL;
    struct kyk_utxo_chain* updated_utxo_chain = NULL;
    uint8_t* pubkey = NULL;
    size_t pub_len = 0;
    uint64_t mfee = 0;
    int res = -1;

    check(new_blk, "Failed to kyk_wallet_mining_block: new_blk is NULL");
    check(tx, "Failed to kyk_wallet_mining_block: tx_list is NULL");
    check(utxo_list, "Failed to kyk_wallet_mining_block: utxo_list is NULL");
    check(utxo_list -> data, "Failed to kyk_wallet_mining_block: utxo_list -> data is NULL");

    res = kyk_wallet_get_pubkey(&pubkey, &pub_len, wallet, KYK_DEFAULT_PUBKEY_NAME);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_wallet_get_pubkey failed");

    res = kyk_load_blk_header_chain(&hd_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_load_blk_header_chain failed");

    res = kyk_load_utxo_chain(&wallet_utxo_chain, wallet);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_load_utxo_chain failed");    

    res = kyk_utxo_list_to_chain(utxo_list, &tx_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_utxo_list_to_chain failed");

    res = kyk_wallet_get_mfee(tx, tx_utxo_chain, &mfee);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_wallet_get_mfee failed");

    res = kyk_make_tx_block(&blk, hd_chain, tx, mfee, 1, KYK_DEFAULT_NOTE, pubkey, pub_len);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_make_tx_block failed");

    res = kyk_validate_block(hd_chain, blk);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_validate_block failed");

    res = kyk_append_blk_hd_chain(hd_chain, blk -> hd, 1);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_append_blk_hd_chain failed");

    res = kyk_append_utxo_chain_from_block(wallet_utxo_chain, blk);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_append_utxo_chain_from_block failed");

    /* kyk_wallet_set_utxo_chain_spent(tx_utxo_chain); */

    kyk_wallet_consume_utxo_chain(tx_utxo_chain, wallet_utxo_chain);

    res = kyk_remove_spent_utxo(&updated_utxo_chain, wallet_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_remove_spent_utxo failed");

    res = kyk_wallet_save_utxo_chain(wallet, updated_utxo_chain);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_wallet_save_utxo_chain failed");

    res = kyk_save_blk_header_chain(wallet, hd_chain, NULL);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_save_blk_header_chain failed");

    res = kyk_wallet_save_block(wallet, blk);
    check(res == 0, "Failed to kyk_wallet_mining_block: kyk_wallet_save_block failed");
    
    if(new_blk){
	*new_blk = blk;
    } else {
	kyk_free_block(blk);
    }

    free(pubkey);
    kyk_free_utxo_chain(tx_utxo_chain);
    kyk_free_utxo_chain(wallet_utxo_chain);
    free(updated_utxo_chain);
    
    return 0;
    
error:
    
    if(pubkey) free(pubkey);
    if(blk) kyk_free_block(blk);

    if(tx_utxo_chain) kyk_free_utxo_chain(tx_utxo_chain);
    if(wallet_utxo_chain) kyk_free_utxo_chain(wallet_utxo_chain);
    if(updated_utxo_chain) free(updated_utxo_chain);

    return -1;
}


int kyk_wallet_consume_utxo_chain(const struct kyk_utxo_chain* tx_utxo_chain,
				  struct kyk_utxo_chain* wallet_utxo_chain)
{
    struct kyk_utxo* tx_utxo = NULL;
    struct kyk_utxo* w_utxo = NULL;
    size_t i = 0;
    size_t j = 0;
    int res = -1;

    w_utxo = wallet_utxo_chain -> hd;
    for(i = 0; i < wallet_utxo_chain -> len; i++){
	tx_utxo = tx_utxo_chain -> hd;
	for(j = 0; j < tx_utxo_chain -> len; j++){
	    res = kyk_cmp_utxo(tx_utxo, w_utxo);
	    if(res == 0){
		tx_utxo -> refer_to = w_utxo;
		tx_utxo -> spent = 1;
		w_utxo -> spent = 1;
	    }
	    tx_utxo = tx_utxo -> next;
	}
	
	w_utxo = w_utxo -> next;
    }

    return 0;
}

