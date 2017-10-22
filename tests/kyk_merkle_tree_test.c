#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_utils.h"
#include "kyk_mkl_tree.h"


void build_tx_buf_from_hex(struct kyk_tx_buf *tx_buf, const char *hexstr);
void free_tx_buf_list(struct kyk_tx_buf *buf_list, size_t len);

int main()
{
    char *tx1_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac00000000";
    char *tx2_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    struct kyk_tx_buf buf_list[2];
    struct kyk_mkltree_level *leaf_level;
    struct kyk_mkltree_level *root_level;

    build_tx_buf_from_hex(buf_list, tx1_hex);
    build_tx_buf_from_hex(buf_list+1, tx2_hex);
    leaf_level = create_mkl_leafs(buf_list, 2);
    root_level = create_mkl_tree(leaf_level);

    /* printf("level len: %zu\n", pnt_level -> len); */
    /* printf("level inx: %zu\n", pnt_level -> inx); */

    kyk_print_hex("Merkle Root Hash", root_level -> nd -> bdy, MKL_NODE_BODY_LEN);
    /* for(int i=0; i < leaf_level -> len; i++){ */
    /* 	kyk_print_hex("leaf Hash", leaf_level -> nd[i].bdy, MKL_NODE_BODY_LEN); */
    /* } */
    free_tx_buf_list(buf_list, sizeof(buf_list)/sizeof(buf_list[0]));

}


void build_tx_buf_from_hex(struct kyk_tx_buf *tx_buf, const char *hexstr)
{
    tx_buf -> bdy = kyk_alloc_hex(hexstr, &tx_buf -> len);    
}

void free_tx_buf_list(struct kyk_tx_buf *buf_list, size_t len)
{
    for(int i = 0; i < len; i++){
	free(buf_list[i].bdy);
    }
}




    











