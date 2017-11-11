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

#endif
