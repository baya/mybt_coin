#ifndef BTC_MESSAGE_H__
#define BTC_MESSAGE_H__

#include "kyk_defs.h"
#include "kyk_block.h"

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

#define KYK_MSG_TYPE_PING       "ping"
#define KYK_MSG_TYPE_PONG       "pong"
#define KYK_MSG_TYPE_VERSION    "version"
#define KYK_MSG_TYPE_GETHEADERS "getheaders"
#define KYK_MSG_TYPE_HEADERS    "headers"
#define KYK_MSG_TYPE_GETDATA    "getdata"
#define KYK_MSG_TYPE_BLOCK      "block"
#define KYK_MSG_TYPE_TX         "tx"

#define PTL_INV_ERROR              0
#define PTL_INV_MSG_TX             1
#define PTL_INV_MSG_BLOCK          2
#define PTL_INV_MSG_FILTERED_BLOCK 3
#define PTL_INV_MSG_CMPCT_BLOCK    4


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

typedef struct protocol_btc_version_entity{
    int32_t vers;
    uint64_t servs;
    int64_t ttamp;
    ptl_net_addr *addr_recv_ptr;
    ptl_net_addr *addr_from_ptr;
    uint64_t nonce;
    uint8_t ua_len;
    char*   uagent;
    int32_t start_height;
    uint8_t relay;
} ptl_ver_entity;

typedef struct protocol_getheaders_entity{
    uint32_t version;           /* the protocol version */
    varint_t hash_count;        /* number of block locator hash entries */
    uint256* locator_hashes;    /* block locator object; newest back to genesis block (dense to start, but then sparse) */
    uint256 hash_stop;          /* hash of the last desired block header; set to zero to get as many blocks as possible (2000) */
} ptl_gethder_entity;

struct ptl_ping_entity{
    uint64_t nonce;
};

struct ptl_inv {
    uint32_t type;
    char hash[32];
};

int kyk_build_new_ptl_message(ptl_message** new_msg,
			      const char* cmd,
			      uint32_t nt_magic,
			      const ptl_payload* pld);

int kyk_build_ptl_message(ptl_message* msg, const char* cmd, uint32_t nt_magic, const ptl_payload* pld);
int kyk_copy_new_ptl_payload(ptl_payload** new_pld, const ptl_payload* src_pld);
int kyk_new_ptl_payload(ptl_payload** new_pld);

/* ptl_message * unpack_resp_buf(ptl_resp_buf *resp_buf); */
void format_msg_buf(char *str, const ptl_msg_buf *msg_buf);
unsigned int pack_ptl_net_addr(unsigned char *, ptl_net_addr *);

/* calloc methods */
int kyk_new_msg_buf(ptl_msg_buf** new_msg_buf, uint32_t len);


/* free methods */
void kyk_free_ptl_msg(ptl_message* msg);
void kyk_free_ptl_payload(ptl_payload* pld);
void kyk_free_ptl_msg_buf(ptl_msg_buf* msg_buf);
void kyk_free_ptl_gethder_entity(ptl_gethder_entity* entity);

/* serialize message to buffer */
int kyk_seri_ptl_message(ptl_msg_buf *msg_buf, const ptl_message* msg);
int kyk_new_seri_ptl_message(ptl_msg_buf** new_msg_buf, const ptl_message* msg);

/* deserialize buffer to message */
int kyk_deseri_new_ptl_message(ptl_message** new_ptl_msg, const uint8_t* buf, size_t buf_len);

/* build payload */
int kyk_build_new_ping_payload(ptl_payload** new_pld, const struct ptl_ping_entity* et);
int kyk_new_ping_entity(struct ptl_ping_entity** new_et);
int kyk_new_seri_ver_entity_to_pld(ptl_ver_entity* ver, ptl_payload** new_pld);
int kyk_seri_version_entity_to_pld(ptl_ver_entity* ver, ptl_payload* pld);

int kyk_build_new_version_entity(ptl_ver_entity** new_ver,
				 int32_t vers,
				 const char* ip_src,
				 int port,
				 uint64_t nonce,
				 const char* uagent,
				 uint8_t ua_len,
				 int32_t start_height);


/* util function */
int kyk_get_ptl_msg_size(const ptl_message* msg, size_t* msg_size);
int kyk_get_ptl_net_addr_size(ptl_net_addr* net_addr, size_t* net_addr_size);
int kyk_get_ptl_ver_entity_size(ptl_ver_entity* ver, size_t* entity_size);
int kyk_get_gethder_entity_size(ptl_gethder_entity* et, size_t* elen);

/* print functions */
void kyk_print_ptl_message(ptl_message* ptl_msg);
void kyk_print_ptl_version_entity(ptl_ver_entity* ver);

/* build payload methods */
int kyk_build_new_pong_payload(ptl_payload** new_pld, uint64_t nonce);
int kyk_build_new_getheaders_entity(ptl_gethder_entity** new_entity,
				    uint32_t version);
int kyk_deseri_new_version_entity(ptl_ver_entity** new_ver_entity, uint8_t* buf, size_t* checknum);
int kyk_deseri_new_net_addr(ptl_net_addr** new_net_addr, uint8_t* buf, size_t* checknum);

int kyk_new_seri_gethder_entity_to_pld(ptl_gethder_entity* et, ptl_payload** new_pld);

int kyk_seri_hd_chain_to_new_pld(ptl_payload** new_pld, const struct kyk_blk_hd_chain* hd_chain);
int kyk_get_headers_pld_len(const struct kyk_blk_hd_chain* hd_chain, size_t* pld_len);

int kyk_deseri_headers_msg_to_new_hd_chain(ptl_message* msg, struct kyk_blk_hd_chain** new_hd_chain);

int kyk_seri_ptl_inv(uint8_t* buf, const struct ptl_inv* inv, size_t* checknum);

int kyk_seri_ptl_inv_list_to_new_pld(ptl_payload** new_pld,
				     const struct ptl_inv* inv_list,
				     varint_t inv_count);

int kyk_hd_chain_to_inv_list(const struct kyk_blk_hd_chain* hd_chain,
			     uint32_t type,
			     struct ptl_inv** new_inv_list,
			     varint_t* inv_count);

int kyk_deseri_ptl_inv(const uint8_t* buf, struct ptl_inv* inv, size_t* checknum);

int kyk_deseri_new_ptl_inv_list(const uint8_t* buf,
				struct ptl_inv** new_inv_list,
				varint_t* inv_count);

void kyk_print_inv(const struct ptl_inv* inv);

void kyk_print_inv_list(const struct ptl_inv* inv_list, varint_t inv_count);

#endif
