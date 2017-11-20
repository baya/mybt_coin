#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "kyk_sha.h"
#include "kyk_utils.h"
#include "mu_unit.h"

static char message[] = "Hello Bitcoin!";

char* test_kyk_dgst_rmd160()
{
    uint8_t digest[20];
    uint8_t target_digest[20] = {
	0xe7, 0x09, 0x20, 0xd8, 0x38, 0x35, 0x8c, 0x16,
	0xef, 0xa8, 0x6d, 0x49, 0x49, 0x0c, 0xab, 0x44,
	0xae, 0x3d, 0xd8, 0x9f
    };

    kyk_dgst_rmd160(digest, (uint8_t *)message, strlen(message));
    mu_assert(kyk_digest_eq(digest, target_digest, sizeof(digest)), "failed to test_kyk_dgst_rmd160");
    
    return NULL;
}

char* test_kyk_dgst_sha256()
{
    uint8_t digest[32];
    uint8_t target_digest[32] = {
	0x51, 0x8a, 0xd5, 0xa3, 0x75, 0xfa, 0x52, 0xf8,
	0x4b, 0x2b, 0x3d, 0xf7, 0x93, 0x3a, 0xd6, 0x85,
	0xeb, 0x62, 0xcf, 0x69, 0x86, 0x9a, 0x96, 0x73,
	0x15, 0x61, 0xf9, 0x4d, 0x10, 0x82, 0x6b, 0x5c

    };
    kyk_dgst_sha256(digest, (uint8_t*) message, strlen(message));
    mu_assert(kyk_digest_eq(digest, target_digest, sizeof(digest)), "failed to test_kyk_dgst_sha256");

    return NULL;
}

char* test_kyk_dgst_hash256()
{
    uint8_t digest[32];
    uint8_t target_digest[32] = {
	0x90, 0x98, 0x6e, 0xa4, 0xe2, 0x8b, 0x84, 0x7c,
	0xc7, 0xf9, 0xbe, 0xba, 0x87, 0xea, 0x81, 0xb2,
	0x21, 0xca, 0x6e, 0xaf, 0x98, 0x28, 0xa8, 0xb0,
	0x4c, 0x29, 0x0c, 0x21, 0xd8, 0x91, 0xbc, 0xda	
    };
    
    kyk_dgst_hash256(digest, (uint8_t*) message, strlen(message));
    mu_assert(kyk_digest_eq(digest, target_digest, sizeof(digest)), "failed to test_kyk_dgst_hash256");


    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_dgst_rmd160);
    mu_run_test(test_kyk_dgst_sha256);
    mu_run_test(test_kyk_dgst_hash256);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

