#ifndef KYK_VALIDATE_H__
#define KYK_VALIDATE_H__

#include "kyk_defs.h"
#include "varint.h"

struct kyk_blk_hd_chain;
struct kyk_blk_header;
struct kyk_block;
struct kyk_txin;
struct kyk_tx;
struct kyk_txout;

int kyk_validate_blk_header(const struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* outHd);

int kyk_validate_block(const struct kyk_blk_hd_chain* hd_chain,
		       const struct kyk_block* blk);

int kyk_validate_txin_script_sig(const struct kyk_txin* txin,
				 const uint8_t* unsig_buf,
				 size_t unsig_buf_len,
				 const struct kyk_tx* prev_tx);

int kyk_validate_txin_script_sig_with_txout(const struct kyk_txin* txin,
					    const uint8_t* unsig_buf,
					    size_t unsig_buf_len,
					    const struct kyk_txout* txout);

int kyk_validate_tx_txin_script_sig(const struct kyk_tx* tx,
				    varint_t txin_index,
				    const struct kyk_txout* txout);



#endif
