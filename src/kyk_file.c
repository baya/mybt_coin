#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "kyk_file.h"
#include "kyk_utils.h"
#include "dbg.h"

int kyk_file_open(const char* name, bool ro, struct file_descriptor** fdout)
{
    struct file_descriptor* desc;
    int flags = 0;
    
    *fdout = NULL;
    desc = malloc(sizeof *desc);
    check(desc != NULL, "failed to malloc file desc");

    desc -> fd = -1;
    desc -> name = kyk_strdup(name);
    desc -> fp = NULL;

    if (ro) {
	flags |= O_RDONLY;
    } else {
	flags |= O_RDWR;
    }    

    desc -> fd = open(name, flags);
    check(desc > 0, "failed to open: '%s'", name);

    *fdout = desc;

    return 0;

error:
    kyk_free_file_desc(desc);
    return -1;
    
}

void kyk_free_file_desc(struct file_descriptor* desc)
{
    if(desc){
	if(desc -> name) free(desc -> name);
	if(desc -> fp) fclose(desc -> fp);
	if(desc -> fd > 0) close(desc -> fd);
	free(desc);
    }
}

int kyk_file_getline(struct file_descriptor *desc, char **line)
{
    char str[1024];
    char *s;

    *line = NULL;

    if (desc -> fp == NULL) {
	desc -> fp = fdopen(desc -> fd, "ro");
	check(desc -> fp != NULL, "failed to open file '%s'", desc -> name);
    }

    s = fgets(str, sizeof str, desc -> fp);
    if (s == NULL) {
	return 0;
    }

    *line = strdup(str);
    return 0;

error:
    return -1;
}


void kyk_file_close(struct file_descriptor *desc)
{
    kyk_free_file_desc(desc);
}

