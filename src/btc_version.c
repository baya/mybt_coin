#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>

#include "btc_message.h"
#include "kyk_sha.h"
#include "beej_pack.h"
#include "kyk_socket.h"

static void build_version_payload(ptl_ver * , ptl_payload *);
static ptl_net_addr *build_net_addr();

int main(void)
{
    ptl_msg msg;
    ptl_msg *resp_msg;
    ptl_msg_buf msg_buf;
    ptl_ver ver;
    ptl_payload pld;
    ptl_resp_buf resp_buf;
    ptl_msg_buf resp_msg_buf;

    build_version_payload(&ver, &pld);
    build_btc_message(&msg, "version", &pld);
    pack_btc_message(&msg_buf, &msg);

    kyk_send_btc_msg_buf("localhost", "8333", &msg_buf, &resp_buf);
    // kyk_send_btc_msg_buf("seed.bitcoin.sipa.be", "8333", &msg_buf, &resp_buf);
    printf("=======> Response Body:\n");
    printf("%s\n", resp_buf.body);
    printf("\n");
    for(int i =0;i < resp_buf.len; i++){
	printf("%c", resp_buf.body[i]);
    }
	
}


void build_version_payload(ptl_ver * ver, ptl_payload *pld)
{
    //ver -> vers = 70014;
    //ver -> vers = 31900;
    ver -> vers = 70014;
    ver -> servs = NODE_NETWORK;
    //ver -> ttamp = (int64_t)time(NULL);
    //ver -> ttamp = 0x73bc8659;
    //ver -> ttamp = 0x5986bc73;
    ver -> ttamp = (int64_t)time(NULL);
    ver -> addr_recv_ptr = build_net_addr();
    ver -> addr_from_ptr = build_net_addr();
    ver -> nonce = 0;
    //encode_varstr(&(ver -> uagent), "/Satoshi:0.9.2.1/");
    encode_varstr(&(ver -> uagent), "");
    ver -> ua_len = ver -> uagent.len;
    ver -> start_height = 329167;
    //ver -> start_height = 98645;
    ver -> relay = 0;
    pld -> len = 0;
    pack_version(ver, pld);
}


ptl_net_addr *build_net_addr()
{
    ptl_net_addr *na_ptr;
    char *ip_src = "::ffff:127.0.0.1";
    int s, domain;
    
    domain = AF_INET6;

    na_ptr = malloc(sizeof *na_ptr);
    na_ptr -> servs = 1;
    na_ptr -> port = 8333;
    s = inet_pton(domain, LOCAL_IP_SRC, na_ptr -> ipv);
    if (s <= 0) {
	if (s == 0)
	    fprintf(stderr, "Not in presentation format");
	else
	    perror("inet_pton");
	exit(EXIT_FAILURE);
    }

    return na_ptr;
}


