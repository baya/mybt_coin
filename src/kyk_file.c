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
    check(desc -> fd > 0, "failed to open: '%s'", name);

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


int kyk_file_truncate(const struct file_descriptor *desc,
		      uint64_t offset)
{
    int res = 0;

    res = ftruncate(desc -> fd, offset);
    check(res == 0, "FILE: failed to ftruncate");

    return res;

error:
    return -1;
}


int kyk_file_pwrite(const struct file_descriptor *desc,
		    uint64_t offset,
		    const void *buf,
		    size_t len,
		    size_t *numWritten)
{
    ssize_t res;

    if (numWritten) {
	*numWritten = 0;
    }

    do {
#ifdef __CYGWIN__
	/* NOT_TESTED(); */
	res = lseek(desc->fd, 0, SEEK_SET);
	if (res < 0) {
	    break;
	} 
	res = write(desc->fd, buf, len);
#else
	res = pwrite(desc->fd, buf, len, offset);
#endif
    } while (res == -1 && (errno == EAGAIN || errno == EINTR));

    check(res != -1, "failed to kyk_file_pwrite");
    
    if (numWritten) {
	*numWritten = res;
    }
    
    return 0;

error:
    return -1;
}

bool kyk_file_exists(const char *filename)
{
    struct stat s;

    return stat(filename, &s) != -1;
}

int kyk_file_create(const char *filename)
{
    int fd;

    fd = open(filename, O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);
    check(fd >= 0, "failed to create file '%s'", filename);

    close(fd);
    return 0;

error:
    return -1;
}


int kyk_file_mkdir(const char *pathname)
{
    int res;

    res = mkdir(pathname, S_IRWXU | S_IRGRP | S_IROTH);
    check(res >= 0, "failed to create directory: '%s'", pathname);

    return 0;

error:
    return -1;
}


int kyk_file_chmod(const char *filename, uint32_t mode)
{
    int res = 0;

    res = chmod(filename, mode);
    check(res == 0, "failed to chmod '%s'", filename);

    return 0;

error:
    return -1;
}


int kyk_check_create_file(const char *filename,
			  const char *label)
{
    int res = 0;

    if (kyk_file_exists(filename)) {
	return 0;
    }

    res = kyk_file_create(filename);
    check(res == 0, "Failed to create %s file '%s'", label, filename);
    
    res = kyk_file_chmod(filename, 0600);
    check(res == 0, "Failed to chmod 0600 %s file '%s'", label, filename);
    
    return 0;

error:

    return -1;
}
