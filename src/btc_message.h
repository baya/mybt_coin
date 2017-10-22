#ifndef BTC_MESSAGE_H__
#define BTC_MESSAGE_H__


#define NT_MAGIC_MAIN  0xD9B4BEF9
#define NT_MAGIC_TEST  0xDAB5BFFA
#define NT_MAGIC_TEST3 0x0709110B
#define NT_MAGIC_NC    0xFEB4BEF9

#define NODE_NETWORK 1
#define NODE_GETUTXO 2
#define NODE_BLOOM 4

#define LOCAL_IP_SRC "::ffff:127.0.0.1"
#define PL_BUF_SIZE 1024


typedef struct varint {
    uint8_t  va1;
    uint16_t va2;
    uint32_t va4;
    uint64_t va8;
    uint64_t value;
    uint8_t len;
} varint;

typedef struct var_length_string{
    int len;
    char *body;
} var_str;

typedef struct protocol_message_payload {
    uint32_t len;
    unsigned char buf[PL_BUF_SIZE];
} ptl_payload;

typedef struct protocol_btc_message_buf {
    uint32_t len;
    size_t pld_len;
    unsigned char body[PL_BUF_SIZE];
} ptl_msg_buf;

typedef struct protocol_btc_message{
    uint32_t magic;
    char cmd[12];
    uint32_t len;
    char checksum[4];
    ptl_payload *pld_ptr;
} ptl_msg;

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
    unsigned char body[PL_BUF_SIZE];
} ptl_resp_buf;

ptl_msg * unpack_resp_buf(ptl_resp_buf *resp_buf);
void print_msg_buf(const ptl_msg_buf *msg_buf);
void build_btc_message(ptl_msg * msg, const char *cmd, ptl_payload *pld);
void pack_btc_message(ptl_msg_buf *msg_buf, ptl_msg *msg);
void format_msg_buf(char *str, const ptl_msg_buf *msg_buf);
void encode_varstr(var_str *, const char *);
void pack_version(ptl_ver *, ptl_payload *);
unsigned int pack_ptl_net_addr(unsigned char *, ptl_net_addr *);
unsigned int pack_varstr(unsigned char *, var_str);


#endif
