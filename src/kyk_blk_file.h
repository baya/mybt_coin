#ifndef KYK_BLK_FILE_H__
#define KYK_BLK_FILE_H__

struct kyk_blk_file {
    char *filename;
    char *pathname;
    unsigned int nStartPos;
    unsigned int nEndPos;
    int nFile;
    FILE *fp;
};

#endif
