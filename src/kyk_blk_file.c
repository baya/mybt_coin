#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "kyk_blk_file.h"
#include "dbg.h"


void kyk_close_blk_file(struct kyk_blk_file* blk_file)
{
    if(blk_file -> filename) free(blk_file -> filename);
    if(blk_file -> pathname) free(blk_file -> pathname);
    if(blk_file -> fp) fclose(blk_file -> fp);
}

struct kyk_blk_file* kyk_create_blk_file(int nFile, const char* wdir, const char *mode)
{
    struct kyk_blk_file* blk_file = NULL;
    blk_file = malloc(sizeof(struct kyk_blk_file));
    check(blk_file != NULL, "failed to create block file");

    blk_file -> filename = NULL;
    blk_file -> pathname = NULL;
    blk_file -> nStartPos = 0;
    blk_file -> nEndPos = 0;
    blk_file -> nFile = nFile;
    blk_file -> fp = NULL;

    return blk_file;
error:
    if(blk_file) kyk_close_blk_file(blk_file);
    return NULL;
}

