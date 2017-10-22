#ifndef KYK_SER_H__
#define KYK_SER_H__

void kyk_tx_inc_ser(uint8_t **buf_cpy, char *col, ...);
size_t kyk_tx_ser(uint8_t *buf, char *col, ...);
size_t kyk_inc_ser(uint8_t **buf_cpy, char *col, ...);

#endif
