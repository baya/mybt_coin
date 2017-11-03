#ifndef KYK_BLK_FILE_H__
#define KYK_BLK_FILE_H__

struct kyk_blk_file {
    char *filename;
    char *pathname;
    int nOffsetPos;
    unsigned int nStartPos;
    unsigned int nEndPos;
    int nFile;
    FILE *fp;
};

void kyk_close_blk_file(struct kyk_blk_file* blk_file);
struct kyk_blk_file* kyk_create_blk_file(int nFile, const char* blk_dir, const char *mode);

#endif
