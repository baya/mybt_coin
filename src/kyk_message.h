#ifndef BTC_MESSAGE_H__
#define BTC_MESSAGE_H__


#define NT_MAGIC_MAIN  (uint32_t)0xD9B4BEF9
#define NT_MAGIC_TEST  (uint32_t)0xDAB5BFFA
#define NT_MAGIC_TEST3 (uint32_t)0x0709110B
#define NT_MAGIC_NC    (uint32_t)0xFEB4BEF9

#define NODE_NETWORK 1
#define NODE_GETUTXO 2
#define NODE_BLOOM 4

#define LOCAL_IP_SRC "::ffff:127.0.0.1"
#define KYK_PL_BUF_SIZE 1024

#define KYK_MSG_TYPE_LEN 12
#define KYK_MSG_CK_LEN 4
#define KYK_PLD_LEN_POS 16
#define KYK_MSG_HEADER_LEN 24
#define KYK_MSG_TYPE_PING "ping"

typedef struct var_length_string{
    int len;
    char *body;
} var_str;

typedef struct protocol_message_payload {
    uint32_t len;
    uint8_t* data;
} ptl_payload;

typedef struct protocol_btc_message_buf {
    uint32_t len;    
    uint8_t* data;
} ptl_msg_buf;

typedef struct protocol_btc_message{
    uint32_t magic;
    char cmd[KYK_MSG_TYPE_LEN];
    uint32_t pld_len;
    uint8_t checksum[KYK_MSG_CK_LEN];
    ptl_payload *pld;
} ptl_message;

typedef struct protocol_btc_net_addr{
    uint64_t servs;
    unsigned char ipv[16];
    uint16_t port;
} ptl_net_addr;

typedef struct protocol_btc_version{
    int32_t vers;
    uint64_t servs;
    int64_t ttamp;
    ptl_net_addr *addr_recv_ptr;
    ptl_net_addr *addr_from_ptr;
    uint64_t nonce;
    uint8_t ua_len;
    var_str uagent;
    int32_t start_height;
    uint8_t relay;
    uint32_t len;
} ptl_ver;

typedef struct protocol_resp_buf{
    size_t len;
    char cmdname[12];
    uint8_t* data;
} ptl_resp_buf;

struct ptl_ping_entity{
    uint64_t nonce;
};

int kyk_build_btc_new_message(ptl_message** new_msg,
			      const char* cmd,
			      uint32_t nt_magic,
			      const ptl_payload* pld);

int kyk_build_btc_message(ptl_message* msg, const char* cmd, uint32_t nt_magic, const ptl_payload* pld);
int kyk_copy_new_ptl_payload(ptl_payload** new_pld, const ptl_payload* src_pld);
int kyk_new_ptl_payload(ptl_payload** new_pld);

ptl_message * unpack_resp_buf(ptl_resp_buf *resp_buf);
void format_msg_buf(char *str, const ptl_msg_buf *msg_buf);
void kyk_pack_version(ptl_ver *, ptl_payload *);
unsigned int pack_ptl_net_addr(unsigned char *, ptl_net_addr *);
unsigned int kyk_pack_varstr(unsigned char *, var_str);

/* calloc methods */
int kyk_new_msg_buf(ptl_msg_buf** new_msg_buf, uint32_t len);


/* free methods */
void kyk_free_ptl_msg(ptl_message* msg);
void kyk_free_ptl_payload(ptl_payload* pld);
void kyk_free_ptl_msg_buf(ptl_msg_buf* msg_buf);

/* serialize message to buffer */
int kyk_seri_ptl_message(ptl_msg_buf *msg_buf, const ptl_message* msg);
int kyk_new_seri_ptl_message(ptl_msg_buf** new_msg_buf, const ptl_message* msg);

/* deserialize buffer to message */
int kyk_deseri_new_ptl_message(ptl_message** new_ptl_msg, const uint8_t* buf, size_t buf_len);

/* build payload */
int kyk_build_new_ping_payload(ptl_payload** new_pld, const struct ptl_ping_entity* et);
int kyk_new_ping_entity(struct ptl_ping_entity** new_et);

/* util function */
int kyk_get_ptl_msg_size(const ptl_message* msg, size_t* msg_size);
int kyk_encode_varstr(var_str *vstr,
		      const char *src_str,
		      size_t len);


/* print functions */
void kyk_print_ptl_message(ptl_message* ptl_msg);


#endif
