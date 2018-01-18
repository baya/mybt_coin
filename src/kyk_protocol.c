#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "kyk_protocol.h"
#include "kyk_wallet.h"
#include "kyk_utils.h"
#include "beej_pack.h"
#include "kyk_block.h"
#include "kyk_utxo.h"
#include "dbg.h"

/* The ping message is sent primarily to confirm that the TCP/IP connection is still valid. */
/* An error in transmission is presumed to be a closed connection and the address is removed as a current peer. */
int kyk_ptl_ping_req(const char* node,
		     const char* service,
		     ptl_message** rep_msg)
{
    ptl_payload* pld = NULL;
    ptl_message* msg = NULL;
    struct ptl_ping_entity* et = NULL;
    int res = -1;

    res = kyk_new_ping_entity(&et);
    check(res == 0, "Failed to kyk_ptl_ping: kyk_new_ping_entity failed");

    res = kyk_build_new_ping_payload(&pld, et);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_build_new_ptl_message(&msg, KYK_MSG_TYPE_PING, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_ping");

    res = kyk_send_ptl_msg(node, service, msg, rep_msg);
    check(res == 0, "Failed to kyk_ptl_ping");

    return 0;

error:

    return -1;

}

/* The pong message is sent in response to a ping message. In modern protocol versions, a pong response is generated using a nonce included in the ping. */
int kyk_ptl_pong_rep(int sockfd, ptl_message* req_msg)
{
    ptl_payload* pld = NULL;
    ptl_payload* rep_pld = NULL;
    ptl_message* rep_msg = NULL;
    uint64_t nonce = 0;
    int res = -1;
    
    check(req_msg, "Failed to kyk_ptl_pong_rep: req_msg is NULL");

    pld = req_msg -> pld;
    
    check(pld, "Failed to kyk_ptl_pong_rep: pld is NULL");
    check(pld -> data, "Failed to kyk_ptl_pong_rep: pld -> data is NULL");
    
    beej_unpack(pld -> data, "<Q", &nonce);

    res = kyk_build_new_pong_payload(&rep_pld, nonce);
    check(res == 0, "Failed to kyk_ptl_pong_rep: kyk_build_new_pong_payload failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_PONG, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_pong_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_pong_rep");
    

    return 0;

error:

    return -1;
}

/* When a node creates an outgoing connection, it will immediately advertise its version. */
/* The remote node will respond with its version. No further communication is possible until both peers have exchanged their version. */
int kyk_ptl_version_rep(int sockfd, ptl_message* req_msg)
{
    ptl_ver_entity* ver_entity = NULL;
    ptl_message* rep_msg = NULL;
    ptl_ver_entity* ver = NULL;
    ptl_payload* pld = NULL;
    int32_t vers = 70014;
    const char* ip_src = LOCAL_IP_SRC;
    int port = 0;
    uint64_t nonce = 0;
    const char* agent = "/KykMiner:0.0.0.1/";
    int32_t start_height = 0;
    int res = -1;    
    
    port = 8333;
    
    check(req_msg, "Failed to kyk_ptl_version_rep: req_msg is NULL");

    res = kyk_deseri_new_version_entity(&ver_entity, req_msg -> pld -> data, NULL);
    check(res == 0, "Failed to kyk_ptl_version_rep");

    kyk_print_ptl_version_entity(ver_entity);

    res = kyk_build_new_version_entity(&ver, vers, ip_src, port, nonce, agent, strlen(agent), start_height);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_build_new_version_entity failed");

    res = kyk_new_seri_ver_entity_to_pld(ver, &pld);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_new_seri_ver_entity_to_pld failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_VERSION, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_version_rep: kyk_reply_ptl_msg failed");
    
    return 0;

error:

    return -1;
}


int kyk_ptl_headers_rep(int sockfd,
			const ptl_message* req_msg,
			const struct kyk_blk_hd_chain* hd_chain)
{
    ptl_payload* pld = NULL;
    ptl_message* rep_msg = NULL;
    int res = -1;

    check(req_msg, "Failed to kyk_ptl_headers_rep: req_msg is NULL");
    check(hd_chain, "Failed to kyk_ptl_headers_rep: hd_chain is NULL");

    res = kyk_seri_hd_chain_to_new_pld(&pld, hd_chain);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_seri_hd_chain_to_new_pld failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_HEADERS, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_headers_rep: kyk_reply_ptl_msg failed");

    return 0;
    
error:

    return -1;
}

int kyk_ptl_blk_rep(int sockfd,
		    const ptl_message* req_msg,
		    struct kyk_wallet* wallet)
{
    /* struct kyk_block** blk = NULL; */
    struct kyk_block** blk_list = NULL;
    struct ptl_inv* inv_list = NULL;
    struct ptl_inv* inv = NULL;
    ptl_payload* pld = NULL;
    ptl_message* rep_msg = NULL;
    varint_t inv_count = 0;
    varint_t i = 0;
    char* hashstr = NULL;
    char* msg = NULL;
    int res = -1;
    
    check(wallet, "Failed to kyk_ptl_blk_rep: wallet is NULL");
    check(req_msg, "Failed to kyk_ptl_blk_rep: req_msg is NULL");
    check(req_msg -> pld, "Failed to yk_ptl_blk_rep: req_msg -> pld is NULL");

    res = kyk_deseri_new_ptl_inv_list(req_msg -> pld -> data, &inv_list, &inv_count);
    check(res == 0, "Failed to kyk_ptl_blk_rep: kyk_deseri_new_ptl_inv_list failed");

    blk_list = calloc(inv_count, sizeof(*blk_list));
    check(blk_list, "Failed to kyk_ptl_blk_rep: calloc failed");

    for(i = 0; i < inv_count; i++){
	inv = inv_list + i;
	res = kyk_wallet_query_block_by_hashbytes(wallet, (uint8_t*)inv -> hash, &blk_list[i]);
	if(res != 0){
	    hashstr = bytes2hexstr((uint8_t*)inv -> hash, sizeof(inv -> hash));
	    check(hashstr, "Failed to kyk_ptl_blk_rep: bytes2hexstr failed");
	    
	    msg = kyk_asprintf("found no block: %s", hashstr);
	    check(msg, "Failed to kyk_ptl_blk_rep: kyk_asprintf failed");
	    
	    kyk_print_hex("invalid blk hash", (uint8_t*)inv -> hash, sizeof(inv -> hash));
	    kyk_ptl_reject_rep(sockfd, CC_REJECT_INVALID, msg);
	    free(hashstr);
	    free(msg);
	    goto error;
	}
	

    }

    for(i = 0; i < inv_count; i++){
	
	res = kyk_seri_blk_to_new_pld(&pld, blk_list[i]);
	check(res == 0, "Failed to kyk_ptl_blk_rep: kyk_seri_blk_to_new_pld failed");
	
	res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_BLOCK, NT_MAGIC_MAIN, pld);
	check(res == 0, "Failed to kyk_ptl_blk_rep: kyk_build_new_ptl_message failed");

	res = kyk_reply_ptl_msg(sockfd, rep_msg);
	check(res == 0, "Failed to kyk_ptl_blk_rep: kyk_write_ptl_msg failed");

    }

    kyk_free_block_list(blk_list, inv_count);
    
    return 0;

error:
    if(blk_list) kyk_free_block_list(blk_list, inv_count);
    return -1;
}

int kyk_ptl_reject_rep(int sockfd,
		       uint8_t ccode,
		       const char* message)
{
    ptl_payload* pld = NULL;
    ptl_message* rep_msg = NULL;
    var_str* msg = NULL;
    var_str* rsn = NULL;
    int res = -1;

    msg = kyk_new_var_str(message);
    rsn = kyk_new_var_str(message);
    res = kyk_build_new_reject_ptl_payload(&pld, msg, ccode, rsn, NULL, 0);
    check(res == 0, "Failed to kyk_ptl_reject_rep: kyk_build_new_reject_ptl_payload failed");

    res = kyk_build_new_ptl_message(&rep_msg, KYK_MSG_TYPE_REJECT, NT_MAGIC_MAIN, pld);
    check(res == 0, "Failed to kyk_ptl_reject_rep: kyk_build_new_ptl_message failed");

    res = kyk_reply_ptl_msg(sockfd, rep_msg);
    check(res == 0, "Failed to kyk_ptl_reject_rep: kyk_write_ptl_msg failed");

    kyk_free_var_str(msg);
    kyk_free_var_str(rsn);
    kyk_free_ptl_msg(rep_msg);
    kyk_free_ptl_payload(pld);
    
    return 0;

error:

    return -1;
}

int kyk_ptl_tx_rep(int sockfd,
		   const ptl_message* req_msg,
		   struct kyk_wallet* wallet)
{
    struct kyk_tx* tx = NULL;
    struct kyk_utxo_list* utxo_list = NULL;
    ptl_payload* pld = NULL;
    int res = -1;

    check(wallet, "Failed to kyk_ptl_tx_rep: wallet is NULL");
    check(req_msg, "Failed to kyk_ptl_tx_rep: req_msg is NULL");
    check(req_msg -> pld, "Failed to kyk_ptl_tx_rep: req_msg -> pld is NULL");

    pld = req_msg -> pld;

    tx = calloc(1, sizeof(*tx));
    check(tx, "Failed to kyk_ptl_tx_rep: calloc failed");

    res = kyk_deseri_tx(tx, pld -> data, NULL);
    check(res == 0, "Failed to kyk_ptl_tx_rep: kyk_deseri_tx failed");

    utxo_list = calloc(1, sizeof(*utxo_list));
    check(utxo_list, "Failed to kyk_ptl_tx_rep: calloc failed");

    res = kyk_wallet_find_utxo_list_for_tx(wallet, tx, utxo_list);
    check(res == 0, "Failed to kyk_ptl_tx_rep: kyk_wallet_find_utxo_list_for_tx failed");

    /* kyk_print_utxo_list(utxo_list); */
    printf("================== Received Tx:\n");
    kyk_print_tx(tx);

    res = kyk_validate_tx(tx, utxo_list -> data, utxo_list -> len);
    if(res == -1){
	printf("Failed to validate tx \n");
	kyk_ptl_reject_rep(sockfd, CC_REJECT_INVALID, "validate tx failed");
	goto error;
    }

    return 0;
    
error:

    return -1;
}


