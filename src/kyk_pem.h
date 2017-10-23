#ifndef KYK_PEM_H__
#define KYK_PEM_H__

#include <openssl/pem.h>

int get_priv_from_pem(uint8_t *priv, const char *pem_file_name);
char *make_address_from_pem(const char *pem_name);

#endif
