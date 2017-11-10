#ifndef __KEY_H__
#define __KEY_H__

struct kyk_key;

struct kyk_key* kyk_key_alloc(void);
void free_kyk_key(struct kyk_key* k);
struct kyk_key* kyk_key_generate_new(void);

#endif
