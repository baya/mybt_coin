#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "kyk_sha.h"
#include "kyk_utils.h"
#include "kyk_mkl_tree.h"


static void kyk_init_mkltree_node(struct kyk_mkltree_node *nd);
static void kyk_hash_mkl_leaf(struct kyk_mkltree_node *nd, struct kyk_tx_buf buf);
struct kyk_mkltree_level *create_parent_mkl_level(struct kyk_mkltree_level *level);
static void kyk_hash_mkltree_level(struct kyk_mkltree_level *level);
static void kyk_hash_mkltree_node(struct kyk_mkltree_node *nd);
static void kyk_up_mkltree_level(struct kyk_mkltree_level *level, struct kyk_mkltree_level *child_level);
static int root_mkl_level(const struct kyk_mkltree_level *level);
void kyk_init_mkl_level(struct kyk_mkltree_level *level);


void kyk_init_mkltree_node(struct kyk_mkltree_node *nd)
{
    nd -> child_lft = NULL;
    nd -> child_rgt = NULL;
    nd -> pnt = NULL;
    nd -> ntype = LEAF_ND_T;
}

struct kyk_mkltree_level *create_mkl_tree(struct kyk_mkltree_level *leaf_level)
{
    struct kyk_mkltree_level *pnt_level;

    pnt_level = create_parent_mkl_level(leaf_level);
    if(root_mkl_level(pnt_level) == 1){
	return pnt_level;
    } else {
	do{
	    pnt_level = create_parent_mkl_level(pnt_level);
	} while(root_mkl_level(pnt_level) != 1);
    }

    return pnt_level;

}


struct kyk_mkltree_level *create_mkl_leafs(struct kyk_tx_buf *buf_list, size_t len)
{
    struct kyk_mkltree_level *mkl_level = malloc(sizeof(struct kyk_mkltree_level));
    struct kyk_mkltree_node *nd_list = malloc(len * sizeof(struct kyk_mkltree_node));
    struct kyk_mkltree_node *nd = nd_list;
    kyk_init_mkl_level(mkl_level);
    mkl_level -> nd = nd_list;
    mkl_level -> len = 0;
    mkl_level -> inx = 1;
    
    for(int i=0; i < len; i++){
	kyk_init_mkltree_node(nd);
	kyk_hash_mkl_leaf(nd, buf_list[i]);
	mkl_level -> len++;
	nd++;
    }

    if(mkl_level -> len == 1){
	mkl_level -> nd -> ntype = ROOT_ND_T;
    }

    return mkl_level;
}

void kyk_init_mkl_level(struct kyk_mkltree_level *level)
{
    level -> nd = NULL;
    level -> dwn = NULL;
    level -> len = 0;
    level -> inx = 0;
}

void kyk_hash_mkl_leaf(struct kyk_mkltree_node *nd, struct kyk_tx_buf buf)
{
    kyk_dgst_hash256(nd -> bdy, buf.bdy, buf.len);
    kyk_reverse(nd -> bdy, MKL_NODE_BODY_LEN);
}


struct kyk_mkltree_level *create_parent_mkl_level(struct kyk_mkltree_level *level)
{
    struct kyk_mkltree_level *pnt_level;

    if(root_mkl_level(level) == 1){
	pnt_level = level;
    } else {
	pnt_level = malloc(sizeof(struct kyk_mkltree_level));
	kyk_up_mkltree_level(pnt_level, level);
	kyk_hash_mkltree_level(pnt_level);

	if(pnt_level -> len == 1){
	    pnt_level -> nd -> ntype = ROOT_ND_T;
	}
    }

    return pnt_level;
}

int root_mkl_level(const struct kyk_mkltree_level *level)
{
    int res = 0;
    res = level -> len == 1 && level -> nd -> ntype == ROOT_ND_T ? 1 : 0;

    return res;
}


void kyk_hash_mkltree_level(struct kyk_mkltree_level *level)
{    
    for(int i=0; i < level -> len; i++){
	kyk_hash_mkltree_node(level -> nd + i);
    }
}

void kyk_hash_mkltree_node(struct kyk_mkltree_node *nd)
{
    uint8_t tmp_buf[64];

    memcpy(tmp_buf, nd -> child_lft -> bdy, 32);
    kyk_reverse(tmp_buf, 32);
    memcpy(tmp_buf + 32, nd -> child_rgt -> bdy, 32);
    kyk_reverse(tmp_buf + 32, 32);
    kyk_dgst_hash256(nd -> bdy, tmp_buf, sizeof(tmp_buf));
    kyk_reverse(nd -> bdy, MKL_NODE_BODY_LEN);
}

void kyk_up_mkltree_level(struct kyk_mkltree_level *level, struct kyk_mkltree_level *child_level)
{
    size_t len = 0;
    struct kyk_mkltree_node *pnd_cpy;
    if(child_level -> len % 2 == 0){
	len = child_level -> len / 2;
    } else {
	len = child_level -> len / 2 + 1;
    }
    level -> len = len;
    level -> nd = malloc(len * sizeof(struct kyk_mkltree_node));
    level -> inx = child_level -> inx + 1;
    level -> dwn = child_level;
    pnd_cpy = level -> nd;

    for(int i=0; i < level -> len; i++){
	pnd_cpy -> ntype = BR_ND_T;
	pnd_cpy -> child_lft = child_level -> nd + (i * 2);
	if(i * 2 + 1 > child_level -> len - 1){
	    pnd_cpy -> child_rgt = pnd_cpy -> child_lft;
	} else {
	    pnd_cpy -> child_rgt = child_level -> nd + (i * 2 + 1);
	}
	pnd_cpy++;
    }
}

void kyk_print_mkl_tree(const struct kyk_mkltree_level *root_level)
{
    const struct kyk_mkltree_level *lv;

    lv = root_level;

    do{
	kyk_print_mkl_level(lv);
	printf("\n");
	lv = lv -> dwn;
    } while(lv);
}

void kyk_print_mkl_level(const struct kyk_mkltree_level *level)
{
    struct kyk_mkltree_node *nd;
    nd = level -> nd;
    if(root_mkl_level(level) == 1){
	printf("Level %zu (Merkle Root): ", level -> inx);
    } else {
	printf("Level %zu:               ", level -> inx);
    }
    for(int i=0; i < level -> len; i++){
	kyk_inline_print_hex(nd -> bdy, MKL_NODE_BODY_LEN);
	if(i == level -> len -1){
	} else {
	    printf(", ");
	}
	nd++;
    }
}

struct kyk_mkltree_level *create_mkl_leafs_from_txid_hexs(const char *hexs[], size_t row_num)
{
    struct kyk_mkltree_level *mkl_level = malloc(sizeof(struct kyk_mkltree_level));
    struct kyk_mkltree_node *nd_list = malloc(row_num * sizeof(struct kyk_mkltree_node));
    struct kyk_mkltree_node *nd = nd_list;
    
    kyk_init_mkl_level(mkl_level);
    mkl_level -> nd = nd_list;
    mkl_level -> len = 0;
    mkl_level -> inx = 1;
    
    for(int i=0; i < row_num; i++){
	kyk_init_mkltree_node(nd);
	kyk_copy_hex2bin(nd -> bdy, hexs[i], MKL_NODE_BODY_LEN);
	mkl_level -> len++;
	nd++;
    }

    if(mkl_level -> len == 1){
	mkl_level -> nd -> ntype = ROOT_ND_T;
    }

    return mkl_level;
}

void kyk_cpy_mkl_root_value(uint8_t *src, struct kyk_mkltree_level *root_level)
{
    memcpy(src, root_level -> nd -> bdy, MKL_NODE_BODY_LEN);
}



    











