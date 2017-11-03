#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "kyk_utils.h"
#include "kyk_buff.h"
#include "kyk_blk_file.h"
#include "dbg.h"

static char *make_filename(int n);
static char *make_pathname(const char* blk_dir, const char* filename);

void kyk_close_blk_file(struct kyk_blk_file* blk_file)
{
    if(blk_file -> filename) free(blk_file -> filename);
    if(blk_file -> pathname) free(blk_file -> pathname);
    if(blk_file -> fp) fclose(blk_file -> fp);
}

struct kyk_blk_file* kyk_create_blk_file(int nFile, const char* blk_dir, const char *mode)
{
    struct kyk_blk_file* blk_file = NULL;
    blk_file = malloc(sizeof(struct kyk_blk_file));
    check(blk_file != NULL, "failed to create block file");

    blk_file -> filename = make_filename(nFile);
    blk_file -> pathname = make_pathname(blk_dir, blk_file -> filename);
    blk_file -> nOffsetPos = 0;
    blk_file -> nStartPos = 0;
    blk_file -> nEndPos = 0;
    blk_file -> nFile = nFile;
    blk_file -> fp = fopen(blk_file -> pathname, mode);
    check(blk_file -> fp != NULL, "failed to open block file");

    return blk_file;
error:
    if(blk_file) kyk_close_blk_file(blk_file);
    return NULL;
}

char *make_filename(int n)
{
    struct kyk_buff* buf = create_kyk_buff(100);
    size_t len = 0;
    char* filename = NULL;
    check(buf != NULL, "failed to create kyk buff");
    sprintf((char *)buf -> base, "blk%.5i"".dat", n);
    len = strlen((char *)buf -> base) + 1;
    filename = malloc(len * sizeof(char));
    check(filename != NULL, "failed to malloc file name");

    memcpy(filename, (char*)buf->base, len);

    return filename;

    free_kyk_buff(buf);
error:
    if(buf) free_kyk_buff(buf);
    if(filename) free(filename);
    return NULL;
}

char *make_pathname(const char* blk_dir, const char* filename)
{
    char *res = NULL;
    res = kyk_pth_concat(blk_dir, filename);
    check(res != NULL, "failed to make pathname");

    return res;
error:
    return NULL;
}
