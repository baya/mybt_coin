#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "kyk_ecdsa.h"
#include "kyk_utils.h"
#include "kyk_sha.h"
#include "kyk_base58.h"

#define MAIN_NW 0x00

void set_version_byte(uint8_t *vdgst, uint8_t *digest, uint8_t vbyt, size_t len);
void get_addr_checksum(uint8_t *dgst7, const uint8_t *dgst6, size_t len);
void set_chksum_byte(uint8_t *dgst8,
		     uint8_t *dgst7, size_t len1,
		     uint8_t *dgst4, size_t len2);


int main()
{
    /*
     * 0 - Having a private ECDSA key
     */
    uint8_t priv_bytes[32] = {
	0x18,0xE1,0x4A,0x7B,0x6A,0x30,0x7F,0x42,
	0x6A,0x94,0xF8,0x11,0x47,0x01,0xE7,0xC8,
	0xE7,0x74,0xE7,0xF9,0xA4,0x7E,0x2C,0x20,
	0x35,0xDB,0x29,0xA2,0x06,0x32,0x17,0x25
    };

    /* uint8_t priv_bytes[32] = { */
    /* 	0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73, */
    /* 	0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45, */
    /* 	0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3, */
    /* 	0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42 */
    /* }; */
    

    EC_KEY *key;
    uint8_t priv[32];
    const BIGNUM *priv_bn;
    point_conversion_form_t conv_form = POINT_CONVERSION_UNCOMPRESSED;
    size_t pub_len;
    uint8_t *pub, *pub_copy;
    uint8_t *sha_pub;
    uint8_t dgst3[20];
    uint8_t dgst4[21];
    uint8_t dgst5[32];
    uint8_t dgst6[32];
    uint8_t dgst7[4];
    uint8_t dgst8[25];
    char *dgst9;


    key = kyk_ec_new_keypair(priv_bytes);
    if (!key) {
        fprintf(stderr, "Unable to create keypair\n");
        return -1;
    }

    priv_bn = EC_KEY_get0_private_key(key);
    if (!priv_bn) {
        fprintf(stderr, "Unable to decode private key\n");
        return -1;
    }
    BN_bn2bin(priv_bn, priv);
    printf("\nHow to create Bitcoin Address?\n\n");
    printf("0 - Having a private ECDSA key\n");
    kyk_print_hex("", priv, sizeof(priv));
    printf("\n");


    BN_bn2bin(priv_bn, priv);
    EC_KEY_set_conv_form(key, conv_form);
    pub_len = i2o_ECPublicKey(key, NULL);
    pub = calloc(pub_len, sizeof(uint8_t));
    pub_copy = pub;
    
    /*
     * 1 - Take the corresponding public key generated with it
     *     (
     *       65 bytes, 1 byte 0x04,
     *       32 bytes corresponding to X coordinate,
     *       32 bytes corresponding to Y coordinate
     *     )
     *
     */
    if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
	fprintf(stderr, "Unable to decode public key\n");
	return -1;
    }
    printf("1 - Take the corresponding public key generated with it (65 bytes, 1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate)\n");
    kyk_print_hex("", pub, pub_len);
    printf("\n");


    /*
     * 2 - Perform SHA-256 hashing on the public key
     */
    sha_pub = kyk_sha256((char *)pub, pub_len);
    printf("2 - Perform SHA-256 hashing on the public key\n");
    kyk_print_hex("", sha_pub, SHA256_DIGEST_LENGTH);
    printf("\n");

    /*
     * 3 - Perform RIPEMD-160 hashing on the result of SHA-256
     */
    kyk_dgst_rmd160(dgst3, sha_pub, SHA256_DIGEST_LENGTH);
    printf("3 - Perform RIPEMD-160 hashing on the result of SHA-256\n");
    kyk_print_hex("", dgst3, sizeof(dgst3));
    printf("\n");


    /*
     * 4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
     */
    set_version_byte(dgst4, dgst3, MAIN_NW, 20);
    printf("4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)\n");
    kyk_print_hex("", dgst4, sizeof(dgst4));
    printf("\n");


    /*
     * 5 - Perform SHA-256 hash on the extended RIPEMD-160 result
     */
    kyk_dgst_sha256(dgst5, dgst4, sizeof(dgst4));
    printf("5 - Perform SHA-256 hash on the extended RIPEMD-160 result\n");
    kyk_print_hex("", dgst5, sizeof(dgst5));
    printf("\n");

    /*
     * 6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
     */
    kyk_dgst_sha256(dgst6, dgst5, sizeof(dgst5));
    printf("6 - Perform SHA-256 hash on the result of the previous SHA-256 hash\n");
    kyk_print_hex("", dgst6, sizeof(dgst6));
    printf("\n");

    /*
     * 7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
     */

    get_addr_checksum(dgst7, dgst6, sizeof(dgst7));
    printf("7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum\n");
    kyk_print_hex("", dgst7, sizeof(dgst7));
    printf("\n");

    /*
     * 8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
     */

    set_chksum_byte(dgst8, dgst7, sizeof(dgst7), dgst4, sizeof(dgst4));
    printf("8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.\n");
    kyk_print_hex("", dgst8, sizeof(dgst8));
    printf("\n");
    
    
    /*
     * 9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
     */
    dgst9 = kyk_base58(dgst8, sizeof(dgst8));
    printf("9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format\n");
    printf("%s\n", dgst9);
    


    EC_KEY_free(key);
    free(sha_pub);
    free(dgst9);
    
    return 0;
}

void set_version_byte(uint8_t *vdgst, uint8_t *digest, uint8_t vbyt, size_t len)
{
    vdgst[0] = vbyt;
    for (int i=0; i < len; i++){
	vdgst[i+1] = digest[i];
    }
}

void get_addr_checksum(uint8_t *dgst7, const uint8_t *dgst6, size_t len)
{
    for(int i=0; i < len; i++){
	dgst7[i] = dgst6[i];
    }
}


void set_chksum_byte(uint8_t *dgst8,
		     uint8_t *dgst7, size_t len1,
		     uint8_t *dgst4, size_t len2)
{

    for(int i=0; i < len2; i++){
	dgst8[i] = dgst4[i];
    }

    for(int j=0; j < len1; j++){
	dgst8[j+len2] = dgst7[j];
    }

    
}
