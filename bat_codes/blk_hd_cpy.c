int kyk_cpy_blk_header(struct kyk_blk_header* desc_hd,
		       const struct kyk_blk_header* src_hd)
{
    check(desc_hd, "Failed to kyk_cpy_blk_header: desc_hd is NULL");
    check(src_hd, "Failed to kyk_cpy_blk_header: src_hd is NULL");

    desc_hd -> version = src_hd -> version;
    memcpy(desc_hd -> pre_blk_hash, src_hd -> pre_blk_hash, sizeof(desc_hd -> pre_blk_hash));
    memcpy(desc_hd -> mrk_root_hash, src_hd -> mrk_root_hash, sizeof(desc_hd -> mrk_root_hash));
    desc_hd -> tts = src_hd -> tts;
    desc_hd -> bts = src_hd -> bts;
    desc_hd -> nonce = src_hd -> nonce;

    return 0;
    
error:

    return -1;
}
