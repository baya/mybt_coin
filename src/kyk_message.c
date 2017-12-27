#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "beej_pack.h"
#include "kyk_sha.h"
#include "kyk_message.h"
#include "kyk_utils.h"
#include "dbg.h"

static int kyk_copy_ptl_payload(ptl_payload* dest_pld, const ptl_payload* src_pld);


int kyk_build_new_ptl_message(ptl_message** new_msg,
			      const char* cmd,
			      uint32_t nt_magic,
			      const ptl_payload* pld)
{
    ptl_message* msg = NULL;
    int res = -1;
    
    check(new_msg, "Failed to kyk_build_btc_new_message: new_msg is NULL");
    check(cmd, "Failed to kyk_build_btc_new_message: cmd is NULL");
    check(pld, "Failed to kyk_build_btc_new_message: pld is NULL");

    msg = calloc(1, sizeof(*msg));
    check(msg, "Failed to kyk_build_btc_new_message: msg calloc failed");    

    res = kyk_build_ptl_message(msg, cmd, nt_magic, pld);
    check(res == 0, "Failed to kyk_build_btc_new_message");

    *new_msg = msg;

    return 0;
    
error:
    if(msg) kyk_free_ptl_msg(msg);
    return -1;
}


int kyk_build_ptl_message(ptl_message* msg,
			  const char* cmd,
			  uint32_t nt_magic,
			  const ptl_payload* pld)
{
    uint256 digest;
    size_t cmd_len = 0;
    int res = -1;

    check(msg, "Failed to kyk_build_btc_message: msg is NULL");
    check(msg -> pld == NULL, "Failed to kyk_build_btc_message: msg -> pld should be NULL");
    check(pld, "Failed to kyk_build_btc_message: pld is NULL");
    
    cmd_len = strlen(cmd);
    check(cmd_len < sizeof(msg -> cmd), "Failed to kyk_build_btc_message: cmd is invalid");
    
    msg -> magic = nt_magic;
    strcpy(msg -> cmd, cmd);
    msg -> pld_len = pld -> len;

    res = kyk_copy_new_ptl_payload(&msg -> pld, pld);
    check(res == 0, "Failed to kyk_build_btc_message: kyk_copy_new_ptl_payload failed");

    res = kyk_hash256(&digest, pld -> data, pld -> len);
    check(res == 0, "Failed to kyk_build_btc_message: kyk_hash256 failed");
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

    check(new_pld, "Failed to kyk_copy_new_ptl_payload: new_pld is NULL");
    check(src_pld, "Failed to kyk_copy_new_ptl_payload: src_pld is NULL");

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
    dest_pld -> data = calloc(dest_pld -> len, sizeof(*dest_pld -> data));
    check(dest_pld -> data, "Failed to kyk_copy_ptl_payload: calloc failed");
    
    memcpy(dest_pld -> data, src_pld -> data, dest_pld -> len);

    return 0;
    
error:

    return -1;
}

void kyk_free_ptl_msg(ptl_message* msg)
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

ptl_message * unpack_resp_buf(ptl_resp_buf *resp_buf)
{
    unsigned char *bptr = NULL;
    ptl_message *msg = NULL;
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

void kyk_print_ptl_message(ptl_message* ptl_msg)
{
    ptl_msg_buf* msg_buf = NULL;

    kyk_new_seri_ptl_message(&msg_buf, ptl_msg);
    
    printf("ptl_msg -> magic:  %0x\n", ptl_msg -> magic);
    printf("ptl_msg -> cmd:     %s\n", ptl_msg -> cmd);
    printf("ptl_msg -> pld_len: %u\n", ptl_msg -> pld_len);
    kyk_print_hex("ptl_msg -> checksum", ptl_msg -> checksum, sizeof(ptl_msg -> checksum));
    kyk_print_hex("ptl_msg -> pld", ptl_msg -> pld -> data, ptl_msg -> pld_len);
    kyk_print_hex("Hex", msg_buf -> data, msg_buf -> len);
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

int kyk_deseri_new_ptl_message(ptl_message** new_ptl_msg, const uint8_t* buf, size_t buf_len)
{
    const uint8_t* bufp = NULL;
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    
    check(buf, "Failed to kyk_deseri_new_ptl_message: buf is NULL");

    msg = calloc(1, sizeof(*msg));
    check(msg, "Failed to kyk_deseri_new_ptl_message");

    bufp = buf;

    beej_unpack(bufp, "<L", &msg -> magic);
    bufp += sizeof(msg -> magic);

    memcpy(msg -> cmd, bufp, sizeof(msg -> cmd));
    bufp += sizeof(msg -> cmd);

    beej_unpack(bufp, "<L", &msg -> pld_len);
    bufp += sizeof(msg -> pld_len);

    memcpy(msg -> checksum, bufp, sizeof(msg -> checksum));
    bufp += sizeof(msg -> checksum);

    msg -> pld = calloc(1, sizeof(*msg -> pld));
    check(msg -> pld, "Failed to kyk_deseri_new_ptl_message: calloc failed");

    pld = msg -> pld;

    pld -> len = msg -> pld_len;
    pld -> data = calloc(pld -> len, sizeof(*pld -> data));
    check(pld -> data, "Failed to kyk_deseri_new_ptl_message: calloc failed");

    memcpy(pld -> data, bufp, pld -> len);
    bufp += pld -> len;

    if(buf_len > 0){
	check(buf_len == (size_t)(bufp - buf), "Failed to kyk_deseri_new_ptl_message");
    }

    *new_ptl_msg = msg;
  
    return 0;

error:
    if(msg) kyk_free_ptl_msg(msg);
    return -1;
}

int kyk_new_seri_ptl_message(ptl_msg_buf** new_msg_buf, const ptl_message* msg)
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

int kyk_get_ptl_msg_size(const ptl_message* msg, size_t* msg_size)
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
int kyk_seri_ptl_message(ptl_msg_buf* msg_buf, const ptl_message* msg)
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

int kyk_build_new_pong_payload(ptl_payload** new_pld, uint64_t nonce)
{
    ptl_payload* pld = NULL;
    int res = -1;

    res = kyk_new_ptl_payload(&pld);
    check(res == 0, "Failed to kyk_build_new_pong_payload: kyk_new_ptl_payload failed");

    pld -> len = sizeof(nonce);
    pld -> data = calloc(pld -> len, sizeof(*pld -> data));
    check(pld -> data, "Failed to kyk_build_new_pong_payload: pld -> data calloc failed");
    beej_pack(pld -> data, "<Q", nonce);

    *new_pld = pld;

    return 0;
    
error:

    return -1;
}


int kyk_encode_varstr(var_str *vstr,
		      const char *src_str,
		      size_t len)
{
    vstr -> len = len;
    vstr -> body = malloc(len * sizeof(*src_str));
    check(vstr -> body, "Failed to kyk_encode_varstr");
    memcpy(vstr -> body, src_str, len * sizeof(char));

    return 0;
    
error:

    return -1;
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
