#ifndef __KYK_FILE_H__
#define __KYK_FILE_H__

#include "kyk_defs.h"

struct file_descriptor {
   char *name;
   int   fd;
   FILE *fp;
};

void kyk_free_file_desc(struct file_descriptor* desc);
int kyk_file_open(const char* name, bool ro, struct file_descriptor** fdout);
int kyk_file_getline(struct file_descriptor *desc, char **line);
int kyk_file_truncate(const struct file_descriptor *desc,
		      uint64_t offset);

int kyk_file_pwrite(const struct file_descriptor *desc,
		    uint64_t offset,
		    const void *buf,
		    size_t len,
		    size_t *numWritten);

void kyk_file_close(struct file_descriptor *desc);

bool kyk_file_exists(const char *filename);
int kyk_file_create(const char *filename);

#endif
