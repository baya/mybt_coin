#include "kyk_address.h"
#include "dbg.h"


static void set_version_byte(uint8_t *vdgst, uint8_t *digest, uint8_t vbyt, size_t len);
static void get_addr_checksum(uint8_t *dgst7, const uint8_t *dgst6, size_t len);
static void set_chksum_byte(uint8_t *dgst8,
		     uint8_t *dgst7, size_t len1,
		     uint8_t *dgst4, size_t len2);



static uint8_t MAIN_NW = 0x00;

char *kyk_make_address_from_pubkey(uint8_t *pub, size_t pub_len)
{
    uint8_t dgst2[SHA256_DIGEST_LENGTH];
    uint8_t dgst3[20];
    uint8_t dgst4[21];
    uint8_t dgst5[32];
    uint8_t dgst6[32];
    uint8_t dgst7[4];
    uint8_t dgst8[25];
    char *dgst9;

    /*
     * 2 - Perform SHA-256 hashing on the public key
     */
    kyk_dgst_sha256(dgst2, pub, pub_len);
    
    
    /*
     * 3 - Perform RIPEMD-160 hashing on the result of SHA-256
     */
    kyk_dgst_rmd160(dgst3, dgst2, sizeof(dgst2));
    

    /*
     * 4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
     */
    set_version_byte(dgst4, dgst3, MAIN_NW, 20);


    /*
     * 5 - Perform SHA-256 hash on the extended RIPEMD-160 result
     */
    kyk_dgst_sha256(dgst5, dgst4, sizeof(dgst4));
    

    /*
     * 6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
     */
    kyk_dgst_sha256(dgst6, dgst5, sizeof(dgst5));

    
    /*
     * 7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
     */
    get_addr_checksum(dgst7, dgst6, sizeof(dgst7));
    

    /*
     * 8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
     */
    set_chksum_byte(dgst8, dgst7, sizeof(dgst7), dgst4, sizeof(dgst4));


    /*
     * 9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
     */
    dgst9 = kyk_base58(dgst8, sizeof(dgst8));

    return dgst9;

}

char *kyk_make_address(const uint8_t *priv_bytes, size_t priv_len)
{
    EC_KEY *key = NULL;
    point_conversion_form_t conv_form;
    size_t pub_len = 0;
    size_t res = 0;
    uint8_t *pub, *pub_copy;
    char *dgst9;

    if(priv_len == 33){
	/* WIF-compressed */
	if(priv_bytes[priv_len -1] == 0x01){
	    conv_form = POINT_CONVERSION_COMPRESSED;
	}
    } else if(priv_len == 32){
	conv_form = POINT_CONVERSION_UNCOMPRESSED;
    } else {
	printf("Failed to kyk_make_address: invalid priv bytes\n");
	goto error;
    }

    check(priv_bytes, "Failed to kyk_make_address: priv_bytes can not be NULL");

    key = kyk_ec_new_keypair(priv_bytes);
    check(key != NULL, "failed to create keypair");

    EC_KEY_set_conv_form(key, conv_form);
    pub_len = i2o_ECPublicKey(key, NULL);
    pub = calloc(pub_len, sizeof(uint8_t));
    pub_copy = pub;

    /* 1 - Take the corresponding public key generated with it
     *     (
     *       65 bytes, 1 byte 0x04,
     *       32 bytes corresponding to X coordinate,
     *       32 bytes corresponding to Y coordinate
     *     )
     *
     */
    res = (size_t)i2o_ECPublicKey(key, &pub_copy);
    check(res == pub_len, "failed to get public key");
    dgst9 = kyk_make_address_from_pubkey(pub, pub_len);

    EC_KEY_free(key);

    return dgst9;

error:
    if(key) EC_KEY_free(key);
    return NULL;

}


void set_version_byte(uint8_t *vdgst, uint8_t *digest, uint8_t vbyt, size_t len)
{
    vdgst[0] = vbyt;
    size_t i = 0;
    for (i = 0; i < len; i++){
	vdgst[i+1] = digest[i];
    }
}

void get_addr_checksum(uint8_t *dgst7, const uint8_t *dgst6, size_t len)
{
    size_t i = 0;
    
    for(i = 0; i < len; i++){
	dgst7[i] = dgst6[i];
    }
}


void set_chksum_byte(uint8_t *dgst8,
		     uint8_t *dgst7, size_t len1,
		     uint8_t *dgst4, size_t len2)
{
    size_t i = 0;

    for(i = 0; i < len2; i++){
	dgst8[i] = dgst4[i];
    }

    for(i = 0; i < len1; i++){
	dgst8[i+len2] = dgst7[i];
    }

    
}

