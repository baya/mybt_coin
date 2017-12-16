#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "kyk_config.h"
#include "kyk_file.h"
#include "kyk_utils.h"
#include "dbg.h"


static void config_freekvlist(struct KeyValuePair *list);

static bool kyk_config_parseline(char *line,
				 char **key,
				 char **val);

static void kyk_config_chomp(char *str);

static void kyk_config_setunknownkv(struct config *config,
				    const char    *key,
				    const char    *val);

static void kyk_config_insert(struct config *config,
			      struct KeyValuePair *ev);

static struct KeyValuePair* kyk_config_get(const struct config* config,
					   const char* key);


struct config* kyk_config_create(void)
{
    struct config* cfg = NULL;
    cfg = calloc(1, sizeof(*cfg));
    check(cfg != NULL, "calloc config failed");

    return cfg;
error:
    return NULL;
}


int kyk_config_load(const char* fileName, struct config** conf)
{
    struct file_descriptor* fd;
    struct config* cfg = NULL;
    struct KeyValuePair* list;
    int res;

    *conf = NULL;
    list = NULL;

    res = kyk_file_open(fileName, TRUE, &fd);
    check(res == 0, "Failed to open config '%s'", fileName);

    cfg = kyk_config_create();
    check(cfg != NULL, "Failed to create config");

    cfg -> fileName = kyk_strdup(fileName);
    cfg -> list = list;

    while (TRUE) {
	char *line = NULL;
	char *key;
	char *val;
	bool s;

	res = kyk_file_getline(fd, &line);
	check(res == 0, "Failed to getline");
	
	if (line == NULL) {
	    break;
	}

	s = kyk_config_parseline(line, &key, &val);
	free(line);
	check(s == TRUE, "Failed to parseline: '%s'", line);
	
	if (key == NULL) {
	    /* comment in the config file */
	    continue;
	}

	kyk_config_setunknownkv(cfg, key, val);
	free(key);
	free(val);
    }

    kyk_free_file_desc(fd);
    *conf = cfg;

    return 0;
    
error:
    kyk_free_file_desc(fd);
    if(cfg) kyk_config_free(cfg);
    return -1;
}


void kyk_config_free(struct config *conf)
{
    if (conf == NULL) {
	return;
    }
    config_freekvlist(conf->list);
    free(conf -> fileName);
    free(conf);
}


static void config_freekvlist(struct KeyValuePair *list)
{
    struct KeyValuePair *ev;

    ev = list;
    while (ev) {
	struct KeyValuePair *next;

	next = ev -> next;
	if (ev -> type == CONFIG_KV_UNKNOWN || ev -> type == CONFIG_KV_STRING) {
	    free(ev -> u.str);
	}
	free(ev -> key);
	free(ev);
	ev = next;
    }
}


static bool kyk_config_parseline(char *line,
				 char **key,
				 char **val)
{
    size_t len = 0;
    char *ptr = NULL;
    char *k = NULL;
    char *v = NULL;
    char *v0 = NULL;
    int res = 0;

    *key = NULL;
    *val = NULL;

    len = strlen(line);
    if (line[len - 1] == '\n' || line[len - 1] == '\r') {
	line[len - 1] = '\0';
    }

    ptr = line;
    while (*ptr != '\0' && *ptr == ' ') {
	ptr++;
    }
    if (*ptr == '\n' || *ptr == '\0') {
	return TRUE;
    }
    if (*ptr == '#') {
	return TRUE;
    }

    k = malloc(len + 1);
    check(k != NULL, "Failed to malloc");
    
    v = malloc(len + 1);
    check(v != NULL, "Failed to malloc");

    res = sscanf(ptr, "%[^=]=%[^\n]", k, v);
    check(res == 2, "Failed to parse '%s'", ptr);

    kyk_config_chomp(k);
    kyk_config_chomp(v);

    v0 = v;
    while (*v != '\0' && *v == ' ') {
	v++;
    }
    if (v[0] == '\"') {
	char *l;
	v++;
	l = strrchr(v, '\"');
	check(l != v, "Failed to parse string: '%s'", v);
	*l = '\0';
    }
    v = kyk_strdup(v);
    free(v0);

    *key = k;
    *val = v;
    return TRUE;

error:
    
    if(k) free(k);
    if(v) free(v);
    if(v0) free(v0);
    
    return FALSE;
}


static void kyk_config_chomp(char *str)
{
   ssize_t i = strlen(str) - 1;

   check(i >= 0, "Failed to chomp %s", str);

   while (i > 0 && str[i] == ' ') {
      str[i] = '\0';
      i--;
   }

error:
   return;
}


static void kyk_config_setunknownkv(struct config *config,
				    const char    *key,
				    const char    *val)
{
    struct KeyValuePair *ev;

    ev = malloc(sizeof *ev);
    check(ev != NULL, "Failed to malloc");
    ev -> key   = kyk_strdup(key);
    ev -> u.str = kyk_strdup(val);
    ev -> type  = CONFIG_KV_UNKNOWN;
    ev -> save  = 1;

    kyk_config_insert(config, ev);

error:
    return;
}


static void kyk_config_insert(struct config *config,
			      struct KeyValuePair *ev)
{
    struct KeyValuePair *prev = NULL;
    struct KeyValuePair *item;

    item = config->list;

    while (item && strcmp(item -> key, ev -> key) < 0) {
	prev = item;
	item = item->next;
    }
    if (prev) {
	ev -> next = prev -> next;
	prev -> next = ev;
    } else {
	ev -> next = config -> list;
	config -> list = ev;
    }
}

void kyk_print_config(struct config* cfg)
{
    struct KeyValuePair* item = cfg -> list;
    check(item != NULL, "you are printing a blank config");
    printf("config file name is %s\n", cfg -> fileName);
    while(item){
	printf("%s = %s\n", item -> key, item -> u.str);
	item = item -> next;
    }

error:
    return;
}


char* kyk_config_getstring(struct config *config,
			   const char    *defaultStr,
			   const char    *format,
			   ...)
{
    struct KeyValuePair *ev;
    char key[1024];
    char *res = NULL;
    va_list ap;

    check(config != NULL, "config can not be NULL");
    check(format != NULL, "format can not be NULL");

    va_start(ap, format);
    vsnprintf(key, sizeof key, format, ap);
    va_end(ap);

    ev = kyk_config_get(config, key);

    if (ev) {
	if (ev -> type == CONFIG_KV_UNKNOWN) {
	    ev -> type = CONFIG_KV_STRING;
	} else {
	    check(ev -> type == CONFIG_KV_STRING, "invalid kv type %d", ev -> type);
	}
	res = ev -> u.str ? kyk_strdup(ev -> u.str) : NULL;
    } else {
	res = defaultStr ? kyk_strdup(defaultStr) : NULL;
    }

    return res;
    
error:
    if(res) free(res);
    return NULL;
}


static struct KeyValuePair* kyk_config_get(const struct config* config,
					   const char* key)
{
    struct KeyValuePair *ev;

    check(config != NULL, "config can not be NULL");

    ev = config->list;
    while (ev) {
	if (strcasecmp(ev -> key, key) == 0) {
	    return ev;
	}
	ev = ev -> next;
    }
    
    return NULL;

error:
    
    return NULL;
}

int kyk_config_write(struct config *conf,
		     const char    *filename)
{
    struct file_descriptor *fd = NULL;
    struct KeyValuePair *ev = NULL;
    uint64_t offset = 0;
    int res = 0;
    size_t numBytes = 0;
    char *s = NULL;

    check(conf != NULL, "conf can not be NULL");

    if (filename == NULL) {
	check(conf->fileName != NULL, "filename and conf fileName can not both be NULL");
    } else {
	free(conf -> fileName);
	conf -> fileName = kyk_strdup(filename);
    }
    res = kyk_file_open(conf -> fileName, FALSE, &fd);
    check(res == 0, "Failed to open config '%s'", filename);

    res = kyk_file_truncate(fd, 0);
    check(res == 0, "Failed to kyk_file_truncate '%s'", filename);

    ev = conf -> list;
    
    while (ev) {
	numBytes = 0;
	s = NULL;

	if (ev -> save == 0) {
	    printf("CONFIG: not writing key '%s'\n", ev -> key);
	    ev = ev -> next;
	    continue;
	}

	switch (ev -> type) {
	case CONFIG_KV_INT64:
	    s = kyk_asprintf("%s = \"%lld\"\n", ev -> key, ev -> u.val);
	    break;
	case CONFIG_KV_BOOL:
	    s = kyk_asprintf("%s = \"%s\"\n", ev -> key, ev -> u.trueOrFalse ? "TRUE" : "FALSE");
	    break;
	default:
	    check(ev -> type == CONFIG_KV_UNKNOWN || ev -> type == CONFIG_KV_STRING, "Invalid kv type");
	    if (ev -> u.str) {
		s = kyk_asprintf("%s = \"%s\"\n", ev -> key, ev -> u.str);
	    }
	}

	if (s) {
	    numBytes = 0;
	    res = kyk_file_pwrite(fd, offset, s, strlen(s), &numBytes);
	    check(res == 0 && numBytes == strlen(s), "CONFIG: failed to kyk_file_pwrite");
	    offset += numBytes;
	    free(s);
	}
	ev = ev -> next;
    }

    return 0;

error:
    
    if(s) free(s);
    if (fd) kyk_file_close(fd);
	
    return -1;
}


int kyk_config_setstring(struct config *config,
			 const char    *str,
			 const char    *fmt,
			 ...)
{
    struct KeyValuePair *ev;
    char key[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof key, fmt, ap);
    va_end(ap);

    ev = kyk_config_get(config, key);

    if (ev) {
	check(ev -> type == CONFIG_KV_STRING || ev -> type == CONFIG_KV_UNKNOWN, "CONFIG: Invalid kv type");
	free(ev -> u.str);
	ev -> u.str = NULL;
    } else {
	ev = malloc(sizeof *ev);
	check(ev, "Failed to malloc");
	ev -> key  = kyk_strdup(key);
	ev -> type = CONFIG_KV_STRING;
	kyk_config_insert(config, ev);
    }
    ev -> save = 1;
    ev -> u.str = str ? kyk_strdup(str) : NULL;
    
    return 0;

error:
    return -1;
}


int kyk_config_save(struct config *conf)
{
    return kyk_config_write(conf, NULL);
}


int kyk_config_setint64(struct config *config,
			int64_t          val,
			const char    *fmt,
			...)
{
    struct KeyValuePair *ev;
    char key[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof key, fmt, ap);
    va_end(ap);

    ev = kyk_config_get(config, key);

    if (ev) {
	if (ev -> type == CONFIG_KV_UNKNOWN) {
	    free(ev -> u.str);
	    ev -> u.str = NULL;
	} else {
	    check(ev -> type == CONFIG_KV_INT64, "ev type should be CONFIG_KV_INT64");
	}
    } else {
	ev = malloc(sizeof *ev);
	check(ev, "failed to malloc");
	ev -> key  = kyk_strdup(key);
	ev -> type = CONFIG_KV_INT64;
	kyk_config_insert(config, ev);
    }
    ev -> save = 1;
    ev -> u.val = val;

    return 0;

error:

    return -1;
}


int kyk_config_getint64(struct config *config,
			int64_t* val,
			int64_t       defaultValue,
			const char    *format,
			...)
{
    struct KeyValuePair *ev;
    char key[1024];
    va_list ap;
    int res = -1;

    check(config, "config can not be NULL");
    check(format, "format can not be NULL");

    va_start(ap, format);
    vsnprintf(key, sizeof key, format, ap);
    va_end(ap);

    ev = kyk_config_get(config, key);

    if (ev) {
	if (ev -> type == CONFIG_KV_UNKNOWN) {
	    int64_t v = atoll(ev -> u.str);
	    free(ev -> u.str);
	    ev -> u.val = v;
	    ev -> type = CONFIG_KV_INT64;
	} else {
	    check(ev-> type == CONFIG_KV_INT64, "ev type should be CONFIG_KV_INT64");
	}
	*val = ev -> u.val;
	
    } else {
	res = kyk_config_setint64(config, defaultValue, "%s", key);
	check(res == 0, "failed to kyk_config_seint64");
	ev = kyk_config_get(config, key);
	check(ev, "failed to kyk_config_get");
	
	ev -> save = 0;
	*val = defaultValue;
    }

    return 0;

error:

    return -1;
}

int kyk_config_get_cfg_idx(const struct config* cfg, int* idx)
{
    struct KeyValuePair* ev = NULL;
    
    int res = -1;

    check(cfg, "cfg can not be NULL");
    
    *idx = 0;

    ev = cfg -> list;
    while(ev){
	if(ev -> next == NULL){
	    res = kyk_get_first_digest(ev -> key, idx);
	    check(res == 0, "failed to kyk_get_first_digest");
	    *idx += 1;
	    break;
	} else {
	    ev = ev -> next;
	}
    }

    return 0;

error:

    return -1;
}

int kyk_config_get_item_count(const struct config* cfg,
			      const char* label,
			      size_t* count)
{
    struct KeyValuePair* ev = NULL;
    size_t tmp_count = 0;
    
    check(cfg, "Failed to kyk_config_get_item_count: cfg is NULL");

    ev = cfg -> list;
    if(label == NULL){
	while(ev){
	    tmp_count += 1;
	    ev = ev -> next;
	}

    } else {
	while(ev){
	    if(strstr(ev -> key, label)){
		tmp_count += 1;
	    }
	    ev = ev -> next;
	}
    }

    *count = tmp_count;

    return 0;

error:

    return -1;
}

