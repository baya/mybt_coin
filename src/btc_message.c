#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "beej_pack.h"
#include "kyk_sha.h"
#include "btc_message.h"

static size_t print_hex(const unsigned char *buf, size_t len, int width, char *note);
static size_t format_hex_to_str(char *str, const char *format, const unsigned char *buf, size_t len);

ptl_msg * unpack_resp_buf(ptl_resp_buf *resp_buf)
{
    unsigned char *bptr;
    ptl_msg *msg = malloc(sizeof(ptl_msg));
    ptl_payload *pd = malloc(sizeof(ptl_payload));

    bptr = resp_buf -> body;
    beej_unpack(bptr, "<L", &(msg -> magic));
    bptr += 4;

    memcpy(msg -> cmd, bptr, 12);
    bptr += 12;

    beej_unpack(bptr, "<L", &(msg -> len));
    bptr += 4;

    memcpy(msg -> checksum, bptr, 4);
    bptr += 4;

    pd -> len = msg -> len;
    memcpy(pd -> buf, bptr, pd -> len);

    msg -> pld_ptr = pd;
    

    return msg;
}

void print_msg_buf(const ptl_msg_buf *msg_buf)
{
    const unsigned char *buf = msg_buf -> body;
    size_t len = 0;
    int wth = 36;

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

    for(int i=0; i < msg_buf -> len; i++){
	printf("%02x", msg_buf -> body[i]);
    }

    printf("\n");
}

void format_msg_buf(char *str, const ptl_msg_buf *msg_buf)
{
    const unsigned char *buf = msg_buf -> body;
    size_t len = 0;
    
    str += format_hex_to_str(str, "Magic", buf, sizeof(uint32_t));
    buf += 4;
    
    str += format_hex_to_str(str, "Command", buf, 12);
    buf += 12;
    
    str += format_hex_to_str(str, "Payload Length", buf, sizeof(uint32_t));
    buf += 4;
    
    str += format_hex_to_str(str, "Checksum", buf, sizeof(uint32_t));
    buf += 4;
    
    format_hex_to_str(str, "Payload", buf, msg_buf -> pld_len);
}

static size_t format_hex_to_str(char *str, const char *note, const unsigned char *buf, size_t len)
{
    size_t j = 0;
    size_t ofst = 0;
    
    j = sprintf(str, "%s: ", note);
    ofst += j;
    str += j;
    for(int i=0; i < len; i++){
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
    for(int i=0; i < len; i++){
	printf("%02x", *buf++);
    }

    printf(" ");
    for(int j=len*2; j < width; j++){
	printf(".");
    }

    printf(" %s\n", note);

    return len;
}

void build_btc_message(ptl_msg * msg, const char *cmd, ptl_payload *pld)
{
    unsigned char *dg2;
    
    msg -> magic = NT_MAGIC_MAIN;
    strcpy(msg -> cmd, cmd);
    msg -> len = pld -> len;
    msg -> pld_ptr = pld;
    dg2 = kyk_dble_sha256((char *)pld -> buf, (size_t)pld -> len);
    memcpy(msg -> checksum, dg2, 4);
}

void pack_btc_message(ptl_msg_buf *msg_buf, ptl_msg *msg)
{
    unsigned char *buf = msg_buf -> body;
    size_t size=0;
    
    msg_buf -> len = 0;
    size = beej_pack(buf, "<L", msg -> magic);
    msg_buf -> len += size;
    buf += size;

    size = sizeof(msg -> cmd);
    memcpy(buf, msg -> cmd, size);
    msg_buf -> len += size;
    buf += size;
    
    size = beej_pack(buf, "<L", (msg -> pld_ptr) -> len);
    msg_buf -> len += size;
    buf += size;

    size = sizeof(msg -> checksum);
    memcpy(buf, msg -> checksum, size);
    msg_buf -> len += size;
    buf += size;

    size = msg -> pld_ptr -> len;
    memcpy(buf, msg -> pld_ptr -> buf, size);
    msg_buf -> len += size;
    buf += size;
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

void pack_version(ptl_ver *ver, ptl_payload *pld)
{
    unsigned int size;
    unsigned char *bufp = pld -> buf;
    
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

    size = pack_varstr(bufp, ver -> uagent);
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

unsigned int pack_varstr(unsigned char *bufp, var_str vstr)
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
