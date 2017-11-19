#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "kyk_script.h"
#include "kyk_utils.h"
#include "mu_unit.h"

char* test_p2pkh_sc_from_address()
{
    char* addr = "1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9";
    uint8_t target_pbk_sc[] = {0x76, 0xa9, 0x14, 0xc7, 0x3e, 0x88, 0xdf, 0xa4,
			       0x5a, 0x94, 0x0b, 0xbe, 0xc4, 0xf5, 0x65, 0x4b,
			       0x91, 0x02, 0x54, 0xe8, 0xb5, 0xd7, 0xbe, 0x88,
			       0xac};
    uint8_t pbk_sc[MAX_SC_PUB_LEN];
    size_t pbk_sc_len = 0;

    pbk_sc_len = p2pkh_sc_from_address(pbk_sc, addr);
    mu_assert(pbk_sc_len == sizeof(target_pbk_sc), "failed to get the correct pbk sc len");
    mu_assert(kyk_digest_eq(pbk_sc, target_pbk_sc, pbk_sc_len), "failed to get the correct pbk sc content");
    
    return NULL;
}

char* test_build_p2pkh_sc_from_pubkey()
{
    return NULL;
}

char* all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_p2pkh_sc_from_address);
    mu_run_test(test_build_p2pkh_sc_from_pubkey);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);
