#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "beej_pack.h"
#include "kyk_sha.h"
#include "btc_message.h"
#include "dbg.h"

static size_t print_hex(const unsigned char *buf, size_t len, int width, char *note);
static size_t format_hex_to_str(char *str, const char *format, const unsigned char *buf, size_t len);
static int kyk_copy_ptl_payload(ptl_payload* dest_pld, const ptl_payload* src_pld);


int kyk_build_btc_new_message(ptl_msg** new_msg,
			      const char* cmd,
			      uint32_t nt_magic,
			      const ptl_payload* pld)
{
    ptl_msg* msg = NULL;
    int res = -1;
    
    check(new_msg, "Failed to kyk_build_btc_new_message: new_msg is NULL");
    check(cmd, "Failed to kyk_build_btc_new_message: cmd is NULL");
    check(pld, "Failed to kyk_build_btc_new_message: pld is NULL");

    msg = calloc(1, sizeof(*msg));
    check(msg, "Failed to kyk_build_btc_new_message: msg calloc failed");    

    res = kyk_build_btc_message(msg, cmd, nt_magic, pld);
    check(res == 0, "Failed to kyk_build_btc_new_message");
    

    return 0;
    
error:
    if(msg) kyk_free_ptl_msg(msg);
    return -1;
}


int kyk_build_btc_message(ptl_msg* msg,
			  const char* cmd,
			  uint32_t nt_magic,
			  const ptl_payload* pld)
{
    uint256 digest;
    int res = -1;

    check(msg, "Failed to kyk_build_btc_message: msg is NULL");
    check(msg -> pld == NULL, "Failed to kyk_build_btc_message: msg -> pld should be NULL");
    check(pld, "Failed to kyk_build_btc_message: pld is NULL");
    
    msg -> magic = nt_magic;
    strcpy(msg -> cmd, cmd);
    msg -> pld_len = pld -> len;
    
    res = kyk_copy_new_ptl_payload(&msg -> pld, pld);
    check(res == 0, "Failed to kyk_build_btc_message: kyk_copy_new_ptl_payload failed");
    
    kyk_hash256(&digest, pld -> data, pld -> len);
    memcpy(msg -> checksum, digest.data, sizeof(msg -> checksum));

    return 0;

error:

    return -1;
}

int kyk_new_ptl_payload(ptl_payload** new_pld)
{
    ptl_payload* pld = NULL;

    pld = calloc(1, sizeof(*pld));
    check(pld, "Failed to kyk_new_ptl_payload: pld calloc failed");

    pld -> len = 0;
    pld -> data = NULL;

    *new_pld = pld;

    return 0;

error:

    return -1;
}

int kyk_copy_new_ptl_payload(ptl_payload** new_pld, const ptl_payload* src_pld)
{
    ptl_payload* pld = NULL;
    int res = -1;

    pld = calloc(1, sizeof(*pld));
    check(pld, "Failed to kyk_copy_new_ptl_payload: pld calloc failed");
    
    res = kyk_copy_ptl_payload(pld, src_pld);
    check(res == 0, "Failed to kyk_copy_new_ptl_payload: kyk_copy_ptl_payload failed");

    *new_pld = pld;

    return 0;

error:
    if(pld) kyk_free_ptl_payload(pld);
    return -1;
}

int kyk_copy_ptl_payload(ptl_payload* dest_pld, const ptl_payload* src_pld)
{
    check(dest_pld, "Failed to kyk_copy_ptl_payload: dest_pld is NULL");
    check(src_pld, "Failed to kyk_copy_ptl_payload: src_pld is NULL");

    dest_pld -> len = src_pld -> len;
    memcpy(dest_pld -> data, src_pld -> data, dest_pld -> len);

    return 0;
    
error:

    return -1;
}

void kyk_free_ptl_msg(ptl_msg* msg)
{
    if(msg){
	if(msg -> pld){
	    kyk_free_ptl_payload(msg -> pld);
	    msg -> pld = NULL;
	}
	free(msg);
    }
}

void kyk_free_ptl_payload(ptl_payload* pld)
{
    if(pld){
	if(pld -> data){
	    free(pld -> data);
	    pld -> data = NULL;
	}
	free(pld);
    }
}

ptl_msg * unpack_resp_buf(ptl_resp_buf *resp_buf)
{
    unsigned char *bptr = NULL;
    ptl_msg *msg = NULL;
    ptl_payload *pld = NULL;

    msg = calloc(1, sizeof(*msg));
    pld = calloc(1, sizeof(*pld));

    bptr = resp_buf -> data;
    beej_unpack(bptr, "<L", &(msg -> magic));
    bptr += 4;

    memcpy(msg -> cmd, bptr, 12);
    bptr += 12;

    beej_unpack(bptr, "<L", &msg -> pld_len);
    bptr += 4;

    memcpy(msg -> checksum, bptr, 4);
    bptr += 4;

    pld -> len = msg -> pld_len;
    memcpy(pld -> data, bptr, pld -> len);

    msg -> pld = pld;
    

    return msg;
}

void kyk_print_msg_buf(const ptl_msg_buf *msg_buf)
{
    const unsigned char *buf = msg_buf -> data;
    size_t len = 0;
    int wth = 36;
    size_t i = 0;

    len = print_hex(buf, sizeof(uint32_t), wth, "Magic");
    buf += len;
    len = print_hex(buf, 12, wth, "Command name");
    printf("Command name: %s\n", buf);
    buf += len;
    len = print_hex(buf, sizeof(uint32_t), wth, "Payload size");
    buf += len;

    len = print_hex(buf, 4, wth, "Checksum");
    buf += len;

    len = msg_buf -> len - 24;
    len = print_hex(buf, len, wth, "Payload");
    buf += len;

    for(i=0; i < msg_buf -> len; i++){
	printf("%02x", msg_buf -> data[i]);
    }

    printf("\n");
}

void format_msg_buf(char *str, const ptl_msg_buf *msg_buf)
{
    const unsigned char *buf = msg_buf -> data;
    
    str += format_hex_to_str(str, "Magic", buf, sizeof(uint32_t));
    buf += 4;
    
    str += format_hex_to_str(str, "Command", buf, 12);
    buf += 12;
    
    str += format_hex_to_str(str, "Payload Length", buf, sizeof(uint32_t));
    buf += 4;
    
    str += format_hex_to_str(str, "Checksum", buf, sizeof(uint32_t));
    buf += 4;
    
    format_hex_to_str(str, "Payload", buf, msg_buf -> len);
}

static size_t format_hex_to_str(char *str, const char *note, const unsigned char *buf, size_t len)
{
    size_t j = 0;
    size_t i = 0;
    size_t ofst = 0;
    
    j = sprintf(str, "%s: ", note);
    ofst += j;
    str += j;
    for(i=0; i < len; i++){
	j = sprintf(str, "%02x", buf[i]);
	ofst += j;
        str += j;
    }
    j = sprintf(str, "\n");
    ofst += j;

    return ofst;
}

static size_t print_hex(const unsigned char *buf, size_t len, int width, char *note)
{
    size_t i = 0;
    for(i=0; i < len; i++){
	printf("%02x", *buf++);
    }

    printf(" ");
    for(i = len*2; i < (size_t)width; i++){
	printf(".");
    }

    printf(" %s\n", note);

    return len;
}

void encode_varstr(var_str *vstr, const char *src)
{
    size_t len;

    len = strlen(src);
    // encode_varint(&(vstr -> len), len);
    vstr -> len = len;
    vstr -> body = malloc(len * sizeof(char));
    memcpy(vstr -> body, src, len * sizeof(char));
}

void kyk_pack_version(ptl_ver *ver, ptl_payload *pld)
{
    unsigned int size;
    unsigned char *bufp = pld -> data;
    
    size = beej_pack(bufp, "<l", ver -> vers);
    pld -> len += size;
    bufp += size;

    size = beej_pack(bufp, "<Q", ver -> servs);
    pld -> len += size;
    bufp += size;

    size = beej_pack(bufp, "<q", ver -> ttamp);
    pld -> len += size;
    bufp += size;

    size = pack_ptl_net_addr(bufp, ver -> addr_recv_ptr);
    pld -> len += size;
    bufp += size;

    size = pack_ptl_net_addr(bufp, ver -> addr_from_ptr);
    pld -> len += size;
    bufp += size;

    size = beej_pack(bufp, "<Q", ver -> nonce);
    pld -> len += size;
    bufp += size;

    // size = pack_varint(bufp, ver -> ua_len);
    size = beej_pack(bufp, "<H", 0);
    pld -> len += size;
    bufp += size;

    size = kyk_pack_varstr(bufp, ver -> uagent);
    pld -> len += size;
    bufp += size;

    size = beej_pack(bufp, "<l", ver -> start_height);
    pld -> len += size;
    bufp += size;

    /* size = beej_pack(bufp, "C", ver -> relay); */
    /* pld -> len += size; */
    /* bufp += size; */

}

unsigned int pack_ptl_net_addr(unsigned char *bufp, ptl_net_addr *na)
{
    unsigned int size = 0;
    unsigned int m_size = 0;

    size = beej_pack(bufp, "<Q", na -> servs);
    m_size += size;
    bufp += size;

    size = 16;
    memcpy(bufp, na -> ipv, size);
    m_size += size;
    bufp += size;

    size = beej_pack(bufp, ">H", na -> port);
    m_size += size;
    bufp += size;

    return m_size;
}

unsigned int kyk_pack_varstr(unsigned char *bufp, var_str vstr)
{
    unsigned int size = 0;
    unsigned int m_size = 0;

    if(vstr.len > 0)
    {
	size = vstr.len * sizeof(char);
	memcpy(bufp, vstr.body, size);
	m_size += size;

    }

    return m_size;

}

int kyk_new_ping_entity(struct ptl_ping_entity** new_et)
{
    struct ptl_ping_entity* et = NULL;

    et = calloc(1, sizeof(*et));
    check(et, "Failed to kyk_new_ping_entity: et calloc failed");

    /* rand seeds */
    srand((unsigned)time(NULL));
    
    et -> nonce = (uint64_t)rand();
    *new_et = et;
    
    return 0;
    
error:

    return -1;
}

int kyk_new_seri_ptl_message(ptl_msg_buf** new_msg_buf, const ptl_msg* msg)
{
    ptl_msg_buf* msg_buf = NULL;
    size_t msg_size = 0;
    int res = -1;

    res = kyk_get_ptl_msg_size(msg, &msg_size);
    check(res == 0, "Failed to kyk_new_seri_ptl_message: kyk_get_ptl_msg_size failed");
    
    res = kyk_new_msg_buf(&msg_buf, msg_size);
    check(res == 0, "Failed to kyk_new_seri_ptl_message: kyk_new_msg_buf failed");

    res = kyk_seri_ptl_message(msg_buf, msg);
    check(res == 0, "Failed to kyk_new_seri_ptl_message: kyk_seri_ptl_message failed");

    *new_msg_buf = msg_buf;

    return 0;
    
error:
    if(msg_buf) kyk_free_ptl_msg_buf(msg_buf);
    return -1;
}

int kyk_new_msg_buf(ptl_msg_buf** new_msg_buf, uint32_t len)
{
    ptl_msg_buf* msg_buf = NULL;
    
    check(len > 0, "Failed to kyk_new_msg_buf: len should be > 0");

    msg_buf = calloc(len, sizeof(*msg_buf));
    check(msg_buf, "Failed to kyk_new_msg_buf: msg_buf calloc failed");

    msg_buf -> len = len;
    msg_buf -> data = calloc(len, sizeof(*msg_buf -> data));
    check(msg_buf -> data, "Failed to kyk_new_msg_buf: msg_buf -> data calloc failed");

    *new_msg_buf = msg_buf;

    return 0;
    
error:
    if(msg_buf) kyk_free_ptl_msg_buf(msg_buf);
    return -1;
}

void kyk_free_ptl_msg_buf(ptl_msg_buf* msg_buf)
{
    if(msg_buf){
	if(msg_buf -> data){
	    free(msg_buf -> data);
	    msg_buf -> data = NULL;
	}

	free(msg_buf);
    }
}

int kyk_get_ptl_msg_size(const ptl_msg* msg, size_t* msg_size)
{
    size_t len = 0;
    
    check(msg, "Failed to kyk_get_ptl_msg_size: msg is NULL");
    check(msg_size, "Failed to kyk_get_ptl_msg_size: msg_size is NULL");

    len += sizeof(msg -> magic);
    len += sizeof(msg -> cmd);
    len += sizeof(msg -> pld_len);
    len += sizeof(msg -> checksum);
    len += msg -> pld_len;

    *msg_size = len;

    return 0;
    
error:

    return -1;
}

/*
** Message structure
**
** Field Size|	Description	Data type	Comments
** ----------+----------------------------------------------------------------------------------------------------------------------------------------------
** 4	     |  magic	        uint32_t	Magic value indicating message origin network, and used to seek to next message when stream state is unknown
** ----------+----------------------------------------------------------------------------------------------------------------------------------------------
** 12	     | command	        char[12]	ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
** ----------+----------------------------------------------------------------------------------------------------------------------------------------------
** 4	     | length	        uint32_t	Length of payload in number of bytes
** ----------+----------------------------------------------------------------------------------------------------------------------------------------------
** 4	     | checksum	        uint32_t	First 4 bytes of sha256(sha256(payload))
** ----------+----------------------------------------------------------------------------------------------------------------------------------------------
** ?	     | payload	        uchar[]	        The actual data
** ---------------------------------------------------------------------------------------------------------------------------------------------------------
*/
int kyk_seri_ptl_message(ptl_msg_buf* msg_buf, const ptl_msg* msg)
{
    unsigned char *buf = NULL;
    size_t len = 0;

    check(msg_buf, "Failed to kyk_seri_ptl_message: msg_buf is NULL");
    check(msg, "Failed to kyk_seri_ptl_message: ptl_msg is NULL");
    check(msg -> pld, "Failed to kyk_seri_ptl_message: msg -> pld is NULL");
    check(msg -> pld_len == msg -> pld -> len, "Failed to kyk_seri_ptl_message: invalid msg -> pld_len");

    buf = msg_buf -> data;
    msg_buf -> len = 0;
    len = beej_pack(buf, "<L", msg -> magic);
    msg_buf -> len += len;
    buf += len;

    len = sizeof(msg -> cmd);
    memcpy(buf, msg -> cmd, len);
    msg_buf -> len += len;
    buf += len;
    
    len = beej_pack(buf, "<L", msg -> pld_len);
    msg_buf -> len += len;
    buf += len;

    len = sizeof(msg -> checksum);
    memcpy(buf, msg -> checksum, len);
    msg_buf -> len += len;
    buf += len;

    len = msg -> pld_len;
    memcpy(buf, msg -> pld -> data, len);
    msg_buf -> len += len;
    buf += len;

    return 0;

error:

    return -1;
}



/* build payload */

/* The ping message is sent primarily to confirm that the TCP/IP connection is still valid. An error in transmission is presumed to be a closed connection and the address is removed as a current peer. */
/* Payload: */
/* Field Size	Description	Data type	Comments     */
/* 8	        nonce	        uint64_t	random nonce */

int kyk_build_new_ping_payload(ptl_payload** new_pld, const struct ptl_ping_entity* et)
{
    ptl_payload* pld = NULL;
    int res = -1;

    res = kyk_new_ptl_payload(&pld);
    check(res == 0, "Failed to kyk_build_new_ping_payload: kyk_new_ptl_payload failed");

    pld -> len = sizeof(et -> nonce);
    pld -> data = calloc(pld -> len, sizeof(*pld -> data));
    check(pld -> data, "Failed to kyk_build_new_ping_payload: pld -> data calloc failed");
    beej_pack(pld -> data, "<Q", et -> nonce);

    *new_pld = pld;

    return 0;

error:
    if(pld) kyk_free_ptl_payload(pld);
    return -1;
}
