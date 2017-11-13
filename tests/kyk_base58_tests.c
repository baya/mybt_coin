#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "kyk_utils.h"
#include "kyk_base58.h"
#include "mu_unit.h"

char* test_kyk_base58check()
{
    uint8_t priv[32] = {
	0x6c, 0x85, 0xf3, 0x94, 0x51, 0x41, 0xa6, 0xc4,
	0x37, 0x93, 0x56, 0x5a, 0x17, 0xc3, 0xc4, 0x69,
	0xc4, 0xcb, 0x07, 0x8a, 0x17, 0x35, 0x2c, 0x22,
	0x7a, 0xbb, 0xc8, 0x58, 0x95, 0x1a, 0xa0, 0xf2
    };

    char* res = NULL;
    char* target_res = "po5gXeh6avhvSWbgnT5ZQgYyNTbsbhtTmaKneuUkMEBmHxhea";

    res = kyk_base58check(priv, sizeof(priv));
    mu_assert(strcmp(res, target_res) == 0, "Failed to get the correct base58check result");

    return NULL;
}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_kyk_base58check);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

