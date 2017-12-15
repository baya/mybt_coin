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

static int read_utxo_count(const uint8_t* buf, uint32_t* count);

int kyk_setup_wallet(struct kyk_wallet** outWallet, const char* wdir)
{
    struct kyk_wallet* wallet = NULL;
    int res = -1;
    
    check(outWallet, "Failed to kyk_setup_wallet: wallet is NULL");
    check(wdir, "Failed to kyk_setup_wallet: wdir is NULL");

    wallet = kyk_new_wallet(wdir);
    check(wallet, "Failed to kyk_open_wallet: kyk_new_wallet failed");

    res = kyk_init_wallet(wallet);
    check(res == 0, "Failed to kyk_open_wallet: kyk_init_wallet failed");

    res = save_setup_data_to_wallet(wallet);
    check(res == 0, "failed to init wallet");

    res = kyk_setup_main_address(wallet);
    check(res == 0, "Failed to kyk_setup_wallet: kyk_setup_main_address failed");

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

    res = kyk_save_blk_header_chain(wallet, hd_chain);
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


/* block header chain */
int kyk_save_blk_header_chain(const struct kyk_wallet* wallet,
			    const struct kyk_blk_hd_chain* hd_chain)
{
    FILE* fp = NULL;
    const struct kyk_blk_hd_chain* hdc = NULL;
    struct kyk_bon_buff* bbuf = NULL;
    size_t len = 0;
    int res = -1;
    

    check(wallet, "Failed to kyk_save_blk_head_chain: wallet is NULL");
    check(wallet -> blk_hd_chain_path, "Failed to kyk_save_blk_head_chain: wallet -> blk_hd_chain_path is NULL");
    check(hd_chain, "Failed to kyk_save_blk_head_chain: hd_chain is NULL");

    fp = fopen(wallet -> blk_hd_chain_path, "wb");
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

int kyk_load_utxo_chain(struct kyk_utxo_chain** new_utxo_chain,
			const struct kyk_wallet* wallet)
{
    struct kyk_utxo_chain* utxo_chain = NULL;
    uint8_t* buf = NULL;
    uint8_t* bufp = NULL;
    FILE* fp = NULL;
    unsigned long int chain_len = 0;
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
    	bufp = buf;
    	/* read_utxo_count(bufp, &chain_len); */
	beej_unpack(bufp, "<L", &chain_len);
    	bufp += sizeof(chain_len);

    	res = kyk_deseri_utxo_chain(utxo_chain, bufp, chain_len, NULL);
    	check(res == 0, "Failed to kyk_load_utxo_chain: kyk_deseri_utxo_chain failed");
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
    check(chain_size == buf_size - sizeof(utxo_chain -> len), "Failed to kyk_wallet_save_utxo_chain: kyk_seri_utxo_chain failed");

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

int read_utxo_count(const uint8_t* buf, uint32_t* count)
{
    uint32_t len = 0;
    beej_unpack(buf, "<L", &len);

    *count = len;

    return 0;
}
