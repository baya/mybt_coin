#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kyk_tx.h"
#include "mu_unit.h"

char* test_seri_tx()
{
    return NULL;
}

char* test_make_coinbase_tx()
{
    struct kyk_tx* tx;
    char* note = "this is a coinbase tx";
    uint64_t outValue = 10000000000;
    uint8_t pubkey[33] = {
	0x03, 0xd3, 0xcf, 0xed, 0xe5, 0x6a, 0x79, 0xf6,
	0xb6, 0x90, 0x7a, 0x5f, 0x14, 0x5a, 0x76, 0xcc,
	0x5c, 0xd7, 0x54, 0x9b, 0x24, 0x4f, 0x7d, 0x93,
	0xbb, 0x72, 0xd4, 0xf9, 0xe4, 0x61, 0xb1, 0x46,
	0xa9	
    };
    int res = -1;

    res = kyk_make_coinbase_tx(&tx, note, outValue, pubkey, sizeof(pubkey));
    mu_assert(res == 0, "Failed to kyk_make_coinbase_tx");
    mu_assert(tx -> version == 1, "Failed to test_make_coinbase_tx");

    kyk_free_tx(tx);
    
    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_seri_tx);
    mu_run_test(test_make_coinbase_tx);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
