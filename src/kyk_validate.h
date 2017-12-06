#ifndef KYK_VALIDATE_H__
#define KYK_VALIDATE_H__

struct kyk_blk_hd_chain;
struct kyk_blk_header;
struct kyk_block;

int kyk_validate_blk_header(const struct kyk_blk_hd_chain* hd_chain,
			    const struct kyk_blk_header* outHd);

int kyk_validate_block(const struct kyk_blk_hd_chain* hd_chain,
		       const struct kyk_block* blk);

#endif
