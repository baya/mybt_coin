#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "varint.h"
#include "kyk_tx.h"
#include "kyk_utils.h"
#include "beej_pack.h"

struct kyk_blk_header {
    uint32_t version;
    uint8_t pre_blk_hash[32];
    uint8_t mrk_root_hash[32];
    uint32_t tts;
    uint32_t bts;
    uint32_t nonce;
};

struct kyk_block {
    uint32_t magic_no;
    uint32_t blk_size;
    struct kyk_blk_header *hd;
    varint_t tx_count;
    struct kyk_tx *tx;
};

void kyk_parse_blk(struct kyk_block *blk, FILE *fp);
void kyk_print_blk(struct kyk_block *blk);
void kyk_parse_blk_header(struct kyk_blk_header *blk_hd, FILE *fp);
void kyk_print_blk_header(struct kyk_blk_header *blk_hd);
size_t kyk_fread(void *buf, size_t size, size_t count, FILE *fp, char *format);
size_t kyk_varint_fread(void *buf, FILE *fp);

int main(int argc, char *argv[])
{
    FILE *fp;
    struct kyk_block blk;
    int i = 0;
    int c;
    char *n_value = NULL;

    while ((c = getopt(argc, argv, "n:")) != -1) {
	switch(c){
	case 'n':
	    n_value = optarg;
	    break;
	default:
	    fprintf(stderr, "-n block_count block_file\n");
	    abort();
	}
    }

    if(argc == 1){
	fprintf(stderr, "Usage: -n block_count block_file\n");
	abort();
    }
    
    fp = fopen(argv[optind], "rb");
    while(!feof(fp)){
	if(i > atol(n_value)){
	    break;
	}
	kyk_parse_blk(&blk, fp);
	kyk_print_blk(&blk);
	printf("==========================================================================>block#%d\n", i);
	i++;
    }

    fclose(fp);
}

void kyk_parse_blk(struct kyk_block *blk, FILE *fp)
{
    /* block size 不包括 Magic no 和 Blocksize */
    size_t len = 80;
    size_t tx_size = 0;
    
    kyk_fread(&blk -> magic_no, sizeof(blk -> magic_no), 1, fp, "<L");
    kyk_fread(&blk -> blk_size, sizeof(blk -> blk_size), 1, fp, "<L");
    blk -> hd = (struct kyk_blk_header *) malloc(sizeof(struct kyk_blk_header));
    kyk_parse_blk_header(blk -> hd, fp);
    len += kyk_varint_fread(&blk -> tx_count, fp);
    tx_size = blk -> blk_size - len;
    /* 跳过 Tx 的解析 */
    fseek(fp, tx_size, SEEK_CUR);
}

void kyk_parse_blk_header(struct kyk_blk_header *blk_hd, FILE *fp)
{
    kyk_fread(&blk_hd -> version, sizeof(blk_hd -> version), 1, fp, "<L");
    fread(blk_hd -> pre_blk_hash, sizeof(blk_hd -> pre_blk_hash), 1, fp);
    kyk_reverse(blk_hd -> pre_blk_hash, sizeof(blk_hd -> pre_blk_hash));
    fread(blk_hd -> mrk_root_hash, sizeof(blk_hd -> mrk_root_hash), 1, fp);
    kyk_reverse(blk_hd -> mrk_root_hash, sizeof(blk_hd -> mrk_root_hash));
    kyk_fread(&blk_hd -> tts, sizeof(blk_hd -> tts), 1, fp, "<L");
    kyk_fread(&blk_hd -> bts, sizeof(blk_hd -> bts), 1, fp, "<L");
    kyk_fread(&blk_hd -> nonce, sizeof(blk_hd -> nonce), 1, fp, "<L");
}

void kyk_print_blk(struct kyk_block *blk)
{
    printf("Magic no: %x\n", blk -> magic_no);
    printf("Blocksize: %u\n", blk -> blk_size);
    kyk_print_blk_header(blk -> hd);
    printf("Transaction counter: %llu\n", blk -> tx_count);
}

void kyk_print_blk_header(struct kyk_blk_header *blk_hd)
{
    printf("Version: %x\n", blk_hd -> version);
    kyk_print_hex("hashPrevBlock ", blk_hd -> pre_blk_hash, sizeof(blk_hd -> pre_blk_hash));
    kyk_print_hex("hashMerkleRoot ", blk_hd -> mrk_root_hash, sizeof(blk_hd -> mrk_root_hash));
    printf("Time: %u\n", blk_hd -> tts);
    printf("Bits: %u\n", blk_hd -> bts);
    printf("Nonce: %u\n", blk_hd -> nonce);    
}

size_t kyk_fread(void *buf, size_t size, size_t count, FILE *fp, char *format)
{
    size_t len;
    
    len = fread(buf, size, count, fp);
    beej_unpack((unsigned char *)buf, format, buf);

    return len * size;
}

size_t kyk_varint_fread(void *buf, FILE *fp)
{
    size_t len;
    uint8_t fd;
    
    len = fread(buf, sizeof(uint8_t), 1, fp);
    fd = *(uint8_t*) buf;
    
    if(fd < 0xFD){
    } else if(fd == 0xFD){
	len += kyk_fread(buf, sizeof(uint16_t), 1, fp, "<H");
    } else if(fd == 0xFE) {
	len += kyk_fread(buf, sizeof(uint32_t), 1, fp, "<L");
    } else if(fd == 0xFF) {
	len += kyk_fread(buf, sizeof(uint64_t), 1, fp, "<Q");
    } else {
    }

    return len;
}





