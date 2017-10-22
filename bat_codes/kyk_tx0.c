#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "kyk_tx.h"
#include "kyk_sha.h"
#include "kyk_utils.h"

#define MAX_BUF_SIZE 10000



int main()
{
    unsigned char buf[MAX_BUF_SIZE];
    size_t count;
    struct kyk_tx tx0;
    char *pre_txid = "0000000000000000000000000000000000000000000000000000000000000000";
    char *txin_sc = "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
    char *txout_sc = "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac";
    struct kyk_hash *txid;
    FILE *fp = fopen("tx0-debug.bin", "wb");
    
    tx0.version = 1;
    tx0.vin_sz = 1;
    tx0.lock_time = 0;
    size_t wsize;

    tx0.txin = create_txin(pre_txid,
		       4294967295,
		       77,
		       txin_sc,
		       0xFFFFFFFF);

    tx0.vout_sz = 1;
    tx0.txout = create_txout(5000000000,
			     67,
			     txout_sc);

    count = kyk_seri_tx(buf, &tx0);
    printf("====>-------hex: ");
    print_bytes_in_hex(buf, count);
    
    txid = kyk_inver_hash((char *)buf, count);
    printf("====>hash: ");
    print_bytes_in_hex(txid -> body, txid -> len);
    printf("\n");

    wsize = fwrite(buf, sizeof(buf[0]), count, fp);

    printf("+++++++++%d\n", wsize);
    fclose(fp);

}



