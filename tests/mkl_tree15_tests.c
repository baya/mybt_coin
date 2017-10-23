#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kyk_utils.h"
#include "kyk_mkl_tree.h"
#include "mu_unit.h"

/* 数据来源于: https://webbtc.com/block/00000000000000000630790598c5bf4130d9811515c8dd5c6131ea3c56e48ac8.json */

/* mrkl_tree: [ */
/* "30bdad288cc806283ff393b339c473f62d751e7a70ce92145a456b027d12d3a5", */
/* "e062e9fffabef0745c80a6dd3f362fc999c1665d17afb897642ee88ed2a2e914", */
/* "2e2dd87efdd363b86c2d8411bc7124308014229dd81260d2fbd5039113a5eca9", */
/* "3c1ffffaa498ff809d98e60885a4dc94e1ba15e8467e5cd449bc722ebfba274a", */
/* "7adf950078e747be001a4f12b2fdb9eb45c72bc1f69538065e267778d4c2fb12", */
/* "ad4082d28e29b6861ccae2474a37ccc190a3a69c1f71a9f10fe0e1e85149738d", */
/* "75dc059571f497a2a0e37754ee4937fa860e22b674d684158355c6e27c48657c", */
/* "8e735b0ffd951506a61103b5dfb70e318c289545f67a03e93558ecfc212025ce", */
/* "a17fd3b2726ec26ea26d8ab867a94616abc75cc3806ed12d183f30d861aab445", */
/* "9f510478b9dff8a54153d7b9b055909d1cd54bf25da3a85bdc596e12c5c7e2f5", */
/* "3937b04d839c94400733fe58346b511ad79f15656320111f9bb51a3c381b5b8f", */
/* "1a7e9bacfa99d6a998350424ec8c1dce2ce68772af9a6a8f1f2a339ae732ef9a", */
/* "d27a963ef21e7fa42fa6355c5e467697210aff152386789430122d89a2c34025", */
/* "80aca8525241b2c6283d57304f25dac3fbf2a71e0c334bef7576dc2cfd1c3144", */
/* "484182b062b3409e7b36103465e13c3deadebad5ad1dbb9a3361932e18949645", */
/* "836d4d557e2647300238f70034b5d542f13b47451beb4bb8d84694c01ecfd1a6", */
/* "af2484a06020f6f1ef3710e488facbac820ce3d422745374380a8e8c1ac17a26", */
/* "6984baaf7790ceb3fedc54aa96433e778722bb747dd1c2ed68d17b5206e7137c", */
/* "560e656ee95ee03936fd5aae101865e0d04b262544da95accb9f41b9f89bd958", */
/* "ac11970a5d2c18185861f5a71a5fe2ab64f48773c756ca1fddfee6b7b1e5b109", */
/* "d9e8cf85e775084f82f2b28b0141f46d3f1d59e353c741af05f19048a8c1d83f", */
/* "a9170cba27c600482ecd2d62aa7d1d85a0bf4d389836fb26a28bbdc379d8aafe", */
/* "b86ba3ca365c46ad9d3a57231ed4cc4744de196feaf8c2e2f96945a4e3296293", */
/* "60c350fe8fd02052c5a3594b9ddad4bb05eaff3f2fe643ad6fc28754a3c05f4b", */
/* "295ad05c7a5e65e24ff3e03547debab16defaeaa08ba4c3623691ded970bf1a3", */
/* "ebc7db0f8f9f328c3adc662366a008fe0e8bafc0cf16126ab9c7c8f82807ae54", */
/* "c43fb85079c1f7fda2ca46a209f4c484269d648ed8872730e2ddb3ffb31933c5", */
/* "283c5137336e8c217e8c77cb3a4259bd6336e81f95f35d056c10f18e5b35834e", */
/* "a2744ae6ef243276ec1e5a38b30c53239c9a3d3488f120f089a0d9a3197e3859", */
/* "b607ddc194f7be5e2b1f0df25754f7c2db20b1b50c6c2ce53e34b54bc502d0d9" */
/* ] */

#define TX_COUNT 15

char *test_make_mkl_tree15()
{
    char *txid_hexs[TX_COUNT] = {
	"30bdad288cc806283ff393b339c473f62d751e7a70ce92145a456b027d12d3a5",
	"e062e9fffabef0745c80a6dd3f362fc999c1665d17afb897642ee88ed2a2e914",
	"2e2dd87efdd363b86c2d8411bc7124308014229dd81260d2fbd5039113a5eca9",
	"3c1ffffaa498ff809d98e60885a4dc94e1ba15e8467e5cd449bc722ebfba274a",
	"7adf950078e747be001a4f12b2fdb9eb45c72bc1f69538065e267778d4c2fb12",
	"ad4082d28e29b6861ccae2474a37ccc190a3a69c1f71a9f10fe0e1e85149738d",
	"75dc059571f497a2a0e37754ee4937fa860e22b674d684158355c6e27c48657c",
	"8e735b0ffd951506a61103b5dfb70e318c289545f67a03e93558ecfc212025ce",
	"a17fd3b2726ec26ea26d8ab867a94616abc75cc3806ed12d183f30d861aab445",
	"9f510478b9dff8a54153d7b9b055909d1cd54bf25da3a85bdc596e12c5c7e2f5",
	"3937b04d839c94400733fe58346b511ad79f15656320111f9bb51a3c381b5b8f",
	"1a7e9bacfa99d6a998350424ec8c1dce2ce68772af9a6a8f1f2a339ae732ef9a",
	"d27a963ef21e7fa42fa6355c5e467697210aff152386789430122d89a2c34025",
	"80aca8525241b2c6283d57304f25dac3fbf2a71e0c334bef7576dc2cfd1c3144",
	"484182b062b3409e7b36103465e13c3deadebad5ad1dbb9a3361932e18949645"
    };
    
    struct kyk_mkltree_level *leaf_level;
    struct kyk_mkltree_level *root_level;

    leaf_level = create_mkl_leafs_from_txid_hexs((const char **)txid_hexs, TX_COUNT);
    root_level = create_mkl_tree(leaf_level);

    uint8_t target_rt[MKL_NODE_BODY_LEN];
    kyk_parse_hex(target_rt, "b607ddc194f7be5e2b1f0df25754f7c2db20b1b50c6c2ce53e34b54bc502d0d9");
    int res = kyk_digest_eq(root_level -> nd -> bdy, target_rt, MKL_NODE_BODY_LEN);

    mu_assert(res, "failed to get the correct merkle 15 root");


    return NULL;

}

char *all_tests()
{
    mu_suite_start();
    
    mu_run_test(test_make_mkl_tree15);
    
    return NULL;
}

MU_RUN_TESTS(all_tests);

