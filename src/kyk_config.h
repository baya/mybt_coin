#ifndef __KYK_CONFIG_H__
#define __KYK_CONFIG_H__

#include "kyk_defs.h"

struct KeyValuePair;

struct config {
    char *fileName;
    struct KeyValuePair *list;
};

int kyk_config_load(const char* fileName, struct config **conf);
int kyk_config_write(struct config *conf, const char *filename);
int kyk_config_save(struct config *conf);

void kyk_config_free(struct config *conf);

struct config* kyk_config_create(void);

int kyk_config_setstring(struct config *config,
			 const char *s,
			 const char *fmt, ...);

void kyk_print_config(struct config* cfg);

char* kyk_config_getstring(struct config *config,
			   const char    *defaultStr,
			   const char    *format,
			   ...);

int kyk_config_setint64(struct config *config,
			int64_t          val,
			const char    *fmt,
			...);

int kyk_config_getint64(struct config *config,
			int64_t* val,
			int64_t       defaultValue,
			const char    *format,
			...);

int kyk_config_get_cfg_idx(const struct config* cfg, int* idx);

#endif
