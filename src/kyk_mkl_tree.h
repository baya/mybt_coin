#ifndef KYK_MKL_TREE_H__
#define KYK_MKL_TREE_H__

#define MKL_NODE_BODY_LEN 32

struct kyk_tx;
struct kyk_bon_buff;

enum mkltree_node_type {
    ROOT_ND_T,
    BR_ND_T,
    LEAF_ND_T
};

struct kyk_mkltree_node{
    struct kyk_mkltree_node *child_lft;
    struct kyk_mkltree_node *child_rgt;
    struct kyk_mkltree_node *pnt;
    uint8_t bdy[MKL_NODE_BODY_LEN];
    enum mkltree_node_type ntype;
};

struct kyk_mkltree_level{
    struct kyk_mkltree_node *nd;
    struct kyk_mkltree_level *dwn; /* 指向下级 level */
    size_t len;
    size_t inx;
};


struct kyk_mkltree_level *create_mkl_tree(struct kyk_mkltree_level *leaf_level);
struct kyk_mkltree_level *create_mkl_leafs(struct kyk_bon_buff *buf_list, size_t len);
void kyk_print_mkl_tree(const struct kyk_mkltree_level *root_level);
struct kyk_mkltree_level *create_mkl_leafs_from_txid_hexs(const char *hexs[], size_t row_num);
void kyk_print_mkl_level(const struct kyk_mkltree_level *level);
void kyk_cpy_mkl_root_value(uint8_t *src, struct kyk_mkltree_level *root_level);
struct kyk_mkltree_level* kyk_make_mkl_tree_root_from_tx_list(struct kyk_tx* tx_list,
							      size_t tx_count);


#endif
