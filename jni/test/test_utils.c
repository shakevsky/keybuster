#include <test.h>
#include <skeymaster_key_params.h>
#include <skeymaster_utils.h>
#include <skeymaster_log.h>

static uint8_t g_ekey_example_data[] = {0x30, 0x82, 0x1, 0x9d, 0x2, 0x1, 0x29, 0x4, 0x82, 0x1, 0x44, 0x6d, 0x7b, 0x94, 0x5d, 0xdf, 0x46, 0xf3, 0x2, 0x29, 0x5c, 0xe7, 0x27, 0xb9, 0xda, 0xab, 0x4d, 0xfe, 0xb1, 0x94, 0xac, 0x33, 0x82, 0xc7, 0x67, 0x85, 0x9f, 0x2b, 0x6d, 0x5c, 0xa0, 0x6f, 0x70, 0xcb, 0x8a, 0xe0, 0xae, 0x85, 0x39, 0x96, 0x4c, 0x84, 0x84, 0xad, 0x91, 0xa, 0x6c, 0x60, 0x4, 0xef, 0x7f, 0x9, 0x8f, 0xc9, 0xdc, 0xf6, 0x92, 0x47, 0x2, 0xbd, 0xf7, 0xb7, 0xe0, 0x6, 0xd1, 0xe8, 0xcf, 0xe2, 0x3b, 0x90, 0x9e, 0xa7, 0xbb, 0x4, 0x23, 0x68, 0x46, 0xd, 0x46, 0xa2, 0x6d, 0xc7, 0xae, 0x39, 0xec, 0xff, 0xf9, 0x20, 0x42, 0xfa, 0x1a, 0x1a, 0x78, 0x5d, 0x19, 0xde, 0x83, 0xca, 0x1b, 0x3e, 0x48, 0xd5, 0xd2, 0x99, 0xc, 0xa4, 0xde, 0x7a, 0xc4, 0x47, 0x5d, 0x53, 0xc4, 0x81, 0xda, 0x95, 0x70, 0x4d, 0x18, 0x7e, 0x58, 0x58, 0xb2, 0x41, 0xe2, 0x31, 0x4, 0x27, 0xd, 0x94, 0x73, 0xdd, 0x58, 0x53, 0xd5, 0x6f, 0xe0, 0xd8, 0xaf, 0xdc, 0x67, 0xea, 0x99, 0x2c, 0x1d, 0xd0, 0xd4, 0x12, 0x55, 0x60, 0xcb, 0xb, 0x14, 0x90, 0xab, 0x8, 0xd, 0xec, 0xdb, 0x95, 0x3, 0x57, 0xd1, 0x18, 0xc8, 0xfe, 0xbd, 0x18, 0x1, 0x4f, 0xaa, 0x69, 0xb6, 0x6c, 0x86, 0xc1, 0xd5, 0x67, 0x8e, 0xb8, 0xe4, 0x67, 0x73, 0x89, 0x5d, 0xf0, 0xaf, 0x5, 0x4f, 0xa1, 0x5, 0x1b, 0x36, 0xf1, 0xc5, 0x44, 0x74, 0x16, 0x33, 0xf4, 0xdf, 0x45, 0x29, 0x62, 0xae, 0x28, 0x9b, 0xe4, 0x23, 0x80, 0x87, 0x5c, 0x70, 0x5f, 0xf2, 0x1d, 0xd4, 0x7d, 0xad, 0x23, 0xd0, 0xa5, 0x20, 0xae, 0x30, 0xb5, 0x2b, 0x79, 0x11, 0x7c, 0x44, 0x8c, 0xb2, 0xfa, 0x57, 0x64, 0x15, 0x19, 0xbe, 0xce, 0x7d, 0xcf, 0x20, 0xf9, 0x1d, 0xd2, 0x36, 0x9a, 0x49, 0x3a, 0x63, 0xd8, 0x6e, 0x35, 0xb6, 0xff, 0xcf, 0x8e, 0xe2, 0x3c, 0x8d, 0x17, 0xa8, 0xda, 0x77, 0x2d, 0xae, 0x39, 0x7f, 0x50, 0xca, 0x53, 0x34, 0x83, 0x3d, 0xc8, 0xff, 0x3e, 0xdf, 0x7a, 0x7b, 0x6, 0x86, 0xb, 0xb9, 0x81, 0x76, 0x6c, 0x2c, 0xd7, 0xc6, 0xd2, 0xb9, 0xb0, 0x3d, 0xad, 0x95, 0x51, 0x97, 0x45, 0x8f, 0x4e, 0x54, 0xc4, 0x99, 0x1f, 0x54, 0x8, 0x4b, 0xc8, 0xd4, 0xf5, 0xbe, 0x3f, 0x3f, 0x90, 0xba, 0x1e, 0xf9, 0x4f, 0x67, 0x1e, 0x80, 0x21, 0xba, 0x31, 0x50, 0x30, 0x16, 0x2, 0x4, 0x90, 0x0, 0x13, 0x88, 0xa1, 0xe, 0x4, 0xc, 0x73, 0x2b, 0x23, 0x4, 0xa5, 0x3b, 0x21, 0x48, 0x1b, 0x2b, 0xd2, 0x55, 0x30, 0x1a, 0x2, 0x4, 0x90, 0x0, 0x13, 0x89, 0xa1, 0x12, 0x4, 0x10, 0xed, 0x84, 0x52, 0x27, 0x5c, 0x81, 0xeb, 0x70, 0x2e, 0xc3, 0x33, 0x56, 0xb4, 0x8c, 0x2c, 0x7a, 0x30, 0x1a, 0x2, 0x4, 0x90, 0x0, 0x13, 0x92, 0xa1, 0x12, 0x4, 0x10, 0x73, 0x2f, 0x81, 0x19, 0xf4, 0xc7, 0xe5, 0x0, 0x50, 0x7e, 0x3e, 0xb9, 0xe, 0xe1, 0x74, 0xc1, 0x13, 0x14, 0xd4, 0x25, 0xfb, 0xc7, 0xdd, 0x84, 0x85, 0x64, 0x95, 0x6b, 0x2a, 0xbe, 0xec, 0x86, 0xcc, 0x59, 0x66, 0x16, 0x1e, 0x3f, 0x29, 0xee, 0x35, 0x16, 0x5e, 0x8c, 0x30, 0xcd, 0xd4, 0x20};
static uint8_t *g_ekey_example = g_ekey_example_data;
static size_t g_ekey_example_len = 449;

void set_default_key_request(key_request_t *req)
{
    // 256-AES-GCM
    memset(req, 0, sizeof(key_request_t));
    req->algorithm = KM_ALGORITHM_AES;
    req->purpose = -1;
    req->padding = -1;
    req->digest = KM_DIGEST_NONE;
    req->enc_ver = -1;
    req->mode = KM_MODE_GCM;
    req->key_size = 256;
}

int test_cmd_to_usage(void)
{
    int ret = TEST_FAILED;
    BEGIN_TEST("cmd_to_usage");

    if (0 != strcmp(cmd_to_usage(CMD_ATTACK), USAGE_ATTACK)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_GENERATE), USAGE_GENERATE)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_GET_CHARS), USAGE_GET_CHARS)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_IMPORT), USAGE_IMPORT)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_EXPORT), USAGE_EXPORT)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_UPGRADE), USAGE_UPGRADE)) {
        goto cleanup;
    }
    else if (0 != strcmp(cmd_to_usage(CMD_BEGIN), USAGE_BEGIN)) {
        goto cleanup;
    }

    ret = TEST_SUCCESS;

cleanup:
    END_TEST(ret);
}

int test_hexlify(void)
{
    int ret = TEST_FAILED;
    BEGIN_TEST("hexlify");

    const char *data = "hello";
    size_t len = 5;
    const char *expected = "68656C6C6F";

    char *hexstring = hexlify((const uint8_t *)data, len);
    if (NULL == hexstring) {
        goto cleanup;
    }

    CHECK(0 == memcmp(expected, hexstring, strlen(expected)));

    ret = TEST_SUCCESS;

cleanup:
    END_TEST(ret);
}

int test_copy_vector(void)
{
    int ret = TEST_FAILED;
    BEGIN_TEST("copy_vector");

    vector_t buf = {(uint8_t *)"hello", 5};
    vector_t copy = {0};

    CHECK(KM_RESULT_SUCCESS == copy_vector(&copy, buf.data, buf.len));

    CHECK(copy.len == buf.len && 0 == memcmp(copy.data, buf.data, buf.len));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != copy.data) {
        free(copy.data);
    }
    END_TEST(ret);
}

int test_get_ekey_blob(void)
{
    vector_t ekey = {0};
    km_ekey_blob_t *ekey_blob = NULL;
    int enc_ver = 0;

    int ret = TEST_FAILED;
    BEGIN_TEST("get_ekey_blob");

    CHECK(KM_RESULT_SUCCESS == copy_vector(&ekey, g_ekey_example, g_ekey_example_len));

    CHECK(KM_RESULT_SUCCESS == get_ekey_blob(&ekey_blob, &ekey));

    CHECK(0 == km_get_ASN1_INTEGER(ekey_blob->enc_ver, &enc_ver) && 0x29 == enc_ver);

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    END_TEST(ret);
}

int test_get_ekey_blob_tag(void)
{
    vector_t ekey = {0};
    km_ekey_blob_t *ekey_blob = NULL;
    vector_t iv = {0};
    const char *expected = "\x73\x2B\x23\x04\xA5\x3B\x21\x48\x1B\x2B\xD2\x55";
    size_t expected_len = 12;

    int ret = TEST_FAILED;
    BEGIN_TEST("get_ekey_blob_tag");

    CHECK(KM_RESULT_SUCCESS == copy_vector(&ekey, g_ekey_example, g_ekey_example_len));

    CHECK(KM_RESULT_SUCCESS == get_ekey_blob_tag(&ekey, KM_TAG_EKEY_BLOB_IV, (param_tag_t *)&iv));

    CHECK(expected_len == iv.len && 0 == memcmp(expected, iv.data, expected_len));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != iv.data) {
        free(iv.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    END_TEST(ret);
}

int test_get_ekey_blob_encrypted(void)
{
    vector_t ekey = {0};
    km_ekey_blob_t *ekey_blob = NULL;
    vector_t encrypted = {0};
    const char *expected = "\x6d\x7b\x94\x5d\xdf\x46\xf3\x02\x29\x5c\xe7\x27\xb9\xda\xab\x4d\xfe\xb1\x94\xac\x33\x82\xc7\x67\x85\x9f\x2b\x6d\x5c\xa0\x6f\x70\xcb\x8a\xe0\xae\x85\x39\x96\x4c\x84\x84\xad\x91\x0a\x6c\x60\x04\xef\x7f\x09\x8f\xc9\xdc\xf6\x92\x47\x02\xbd\xf7\xb7\xe0\x06\xd1\xe8\xcf\xe2\x3b\x90\x9e\xa7\xbb\x04\x23\x68\x46\x0d\x46\xa2\x6d\xc7\xae\x39\xec\xff\xf9\x20\x42\xfa\x1a\x1a\x78\x5d\x19\xde\x83\xca\x1b\x3e\x48\xd5\xd2\x99\x0c\xa4\xde\x7a\xc4\x47\x5d\x53\xc4\x81\xda\x95\x70\x4d\x18\x7e\x58\x58\xb2\x41\xe2\x31\x04\x27\x0d\x94\x73\xdd\x58\x53\xd5\x6f\xe0\xd8\xaf\xdc\x67\xea\x99\x2c\x1d\xd0\xd4\x12\x55\x60\xcb\x0b\x14\x90\xab\x08\x0d\xec\xdb\x95\x03\x57\xd1\x18\xc8\xfe\xbd\x18\x01\x4f\xaa\x69\xb6\x6c\x86\xc1\xd5\x67\x8e\xb8\xe4\x67\x73\x89\x5d\xf0\xaf\x05\x4f\xa1\x05\x1b\x36\xf1\xc5\x44\x74\x16\x33\xf4\xdf\x45\x29\x62\xae\x28\x9b\xe4\x23\x80\x87\x5c\x70\x5f\xf2\x1d\xd4\x7d\xad\x23\xd0\xa5\x20\xae\x30\xb5\x2b\x79\x11\x7c\x44\x8c\xb2\xfa\x57\x64\x15\x19\xbe\xce\x7d\xcf\x20\xf9\x1d\xd2\x36\x9a\x49\x3a\x63\xd8\x6e\x35\xb6\xff\xcf\x8e\xe2\x3c\x8d\x17\xa8\xda\x77\x2d\xae\x39\x7f\x50\xca\x53\x34\x83\x3d\xc8\xff\x3e\xdf\x7a\x7b\x06\x86\x0b\xb9\x81\x76\x6c\x2c\xd7\xc6\xd2\xb9\xb0\x3d\xad\x95\x51\x97\x45\x8f\x4e\x54\xc4\x99\x1f\x54\x08\x4b\xc8\xd4\xf5\xbe\x3f\x3f\x90\xba\x1e\xf9\x4f\x67\x1e\x80\x21\xba";
    size_t expected_len = 324;

    int ret = TEST_FAILED;
    BEGIN_TEST("get_ekey_blob_encrypted");

    CHECK(KM_RESULT_SUCCESS == copy_vector(&ekey, g_ekey_example, g_ekey_example_len));

    CHECK(KM_RESULT_SUCCESS == get_ekey_blob_encrypted(&ekey, &encrypted));

    CHECK(expected_len == encrypted.len && 0 == memcmp(expected, encrypted.data, expected_len));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != encrypted.data) {
        free(encrypted.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    END_TEST(ret);
}

int test_add_aad_to_ekey(void)
{
    vector_t ekey = {0};
    km_ekey_blob_t *ekey_blob = NULL;
    vector_t associated = {0};

    const char *expected = "\xB4\x1F\x42\x7E\x59\xD0\xB2\x87\x4B\x64\x0D\x00\x1E\x79\xCE\x67\x27\x4E\x09\x8E\xF2\x1D\xB0\x6B\x75\x52\x2B\x2B\xBC\xF9\x69\x00";
    size_t expected_len = 32;
    vector_t expected_aad = {(uint8_t *)expected, expected_len};

    int ret = TEST_FAILED;
    BEGIN_TEST("add_aad_to_ekey");

    CHECK(KM_RESULT_SUCCESS == copy_vector(&ekey, g_ekey_example, g_ekey_example_len));

    // make sure there's no KM_TAG_ASSOCIATED_DATA before we add
    CHECK(KM_RESULT_INVALID == get_ekey_blob_tag(&ekey, KM_TAG_ASSOCIATED_DATA, (param_tag_t *)&associated));

    // edit ekey blob and compare
    CHECK(KM_RESULT_SUCCESS == add_aad_to_ekey(&expected_aad, &ekey));

    CHECK(KM_RESULT_SUCCESS == get_ekey_blob_tag(&ekey, KM_TAG_ASSOCIATED_DATA, (param_tag_t *)&associated));

    CHECK(expected_len == associated.len && 0 == memcmp(expected, associated.data, expected_len));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != associated.data) {
        free(associated.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    END_TEST(ret);
}


int test_init_basic_param_set(void)
{
    keymaster_key_param_set_t param_set = {0};

    vector_t application_id = {(uint8_t *)"id", 2};
    vector_t application_data = {(uint8_t *)"data", 4};
    vector_t empty = {NULL, 0};

    int ret = TEST_FAILED;
    BEGIN_TEST("init_basic_param_set");

    // no id/data
    CHECK(KM_RESULT_SUCCESS == init_basic_param_set(&empty, &empty, &param_set));
    CHECK(0 == param_set.len);

    // only id
    CHECK(KM_RESULT_SUCCESS == init_basic_param_set(&application_id, &empty, &param_set));
    CHECK(1 == param_set.len);
    CHECK(KM_TAG_APPLICATION_ID == param_set.params[0].tag &&
        0 == memcmp(param_set.params[0].blob.data, application_id.data, application_id.len));

    keymaster_free_param_set(&param_set);

    // only data
    CHECK(KM_RESULT_SUCCESS == init_basic_param_set(&empty, &application_data, &param_set));
    CHECK(1 == param_set.len);
    CHECK(KM_TAG_APPLICATION_DATA == param_set.params[0].tag &&
        0 == memcmp(param_set.params[0].blob.data, application_data.data, application_data.len));
    keymaster_free_param_set(&param_set);

    // both id and data
    CHECK(KM_RESULT_SUCCESS == init_basic_param_set(&application_id, &application_data, &param_set));

    CHECK(2 == param_set.len);
    CHECK(KM_TAG_APPLICATION_ID == param_set.params[0].tag &&
        0 == memcmp(param_set.params[0].blob.data, application_id.data, application_id.len));
    CHECK(KM_TAG_APPLICATION_DATA == param_set.params[1].tag &&
        0 == memcmp(param_set.params[1].blob.data, application_data.data, application_data.len));

    keymaster_free_param_set(&param_set);

    ret = TEST_SUCCESS;

cleanup:
    keymaster_free_param_set(&param_set);

    END_TEST(ret);
}

int test_add_aes_parameters(void)
{
    keymaster_key_param_set_t param_set = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("add_aes_parameters");

    // gcm
    for (int i = 0; i < 2; ++i) {
        memset(&req, 0, sizeof(req));
        req.mode = KM_MODE_GCM;
        if (1 == i) {
            req.nonce.data = (uint8_t *)"nonce";
            req.nonce.len = 5;
        }

        CHECK(0 == add_int_to_param_set(&param_set, KM_TAG_KEY_SIZE, 256));

        CHECK(KM_RESULT_SUCCESS == add_aes_parameters(&req, &param_set));

        if (1 == i) {
            CHECK(7 == param_set.len);
        }
        else {
            CHECK(6 == param_set.len);
        }

        CHECK(KM_TAG_ALGORITHM == param_set.params[1].tag &&
            KM_ALGORITHM_AES == param_set.params[1].integer);

        CHECK(KM_TAG_NO_AUTH_REQUIRED == param_set.params[2].tag &&
            param_set.params[2].boolean);

        CHECK(KM_TAG_BLOCK_MODE == param_set.params[3].tag &&
            KM_MODE_GCM == param_set.params[3].integer);

        CHECK(KM_TAG_MIN_MAC_LENGTH == param_set.params[4].tag &&
            128 == param_set.params[4].integer);

        CHECK(KM_TAG_MAC_LENGTH == param_set.params[5].tag &&
            128 == param_set.params[5].integer);

        if (1 == i) {
            CHECK(KM_TAG_NONCE == param_set.params[6].tag &&
                0 == memcmp(param_set.params[6].blob.data, req.nonce.data, req.nonce.len));
        }

        keymaster_free_param_set(&param_set);
    }

    // not gcm
    for (int i = 0; i < 2; ++i) {
        memset(&req, 0, sizeof(req));
        req.mode = KM_MODE_ECB;
        if (1 == i) {
            req.nonce.data = (uint8_t *)"nonce";
            req.nonce.len = 5;
        }

        CHECK(0 == add_int_to_param_set(&param_set, KM_TAG_KEY_SIZE, 256));

        CHECK(KM_RESULT_SUCCESS == add_aes_parameters(&req, &param_set));

        if (1 == i) {
            CHECK(7 == param_set.len);
        }
        else {
            CHECK(6 == param_set.len);
        }

        CHECK(KM_TAG_ALGORITHM == param_set.params[1].tag &&
            KM_ALGORITHM_AES == param_set.params[1].integer);

        CHECK(KM_TAG_NO_AUTH_REQUIRED == param_set.params[2].tag &&
            param_set.params[2].boolean);

        CHECK(KM_TAG_BLOCK_MODE == param_set.params[3].tag &&
            KM_MODE_ECB == param_set.params[3].integer);

        CHECK(KM_TAG_BLOCK_MODE == param_set.params[4].tag &&
            KM_MODE_CBC == param_set.params[4].integer);

        CHECK(KM_TAG_BLOCK_MODE == param_set.params[5].tag &&
            KM_MODE_CTR == param_set.params[5].integer);

        if (1 == i) {
            CHECK(KM_TAG_NONCE == param_set.params[6].tag &&
                0 == memcmp(param_set.params[6].blob.data, req.nonce.data, req.nonce.len));
        }

        keymaster_free_param_set(&param_set);
    }

    ret = TEST_SUCCESS;

cleanup:
    keymaster_free_param_set(&param_set);

    END_TEST(ret);
}

int test_add_rsa_parameters(void)
{
    keymaster_key_param_set_t param_set = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("add_rsa_parameters");

    memset(&req, 0, sizeof(req));
    req.public_exponent = 0x10001;

    CHECK(0 == add_int_to_param_set(&param_set, KM_TAG_KEY_SIZE, 4096));

    CHECK(KM_RESULT_SUCCESS == add_rsa_parameters(&req, &param_set));

    CHECK(4 == param_set.len);

    CHECK(KM_TAG_ALGORITHM == param_set.params[1].tag &&
        KM_ALGORITHM_RSA == param_set.params[1].integer);

    CHECK(KM_TAG_NO_AUTH_REQUIRED == param_set.params[2].tag &&
        param_set.params[2].boolean);

    CHECK(KM_TAG_RSA_PUBLIC_EXPONENT == param_set.params[3].tag &&
        req.public_exponent == param_set.params[3].integer);

    ret = TEST_SUCCESS;

cleanup:
    keymaster_free_param_set(&param_set);

    END_TEST(ret);
}

int test_add_ec_parameters(void)
{
    keymaster_key_param_set_t param_set = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("add_ec_parameters");

    memset(&req, 0, sizeof(req));

    CHECK(0 == add_int_to_param_set(&param_set, KM_TAG_KEY_SIZE, 4096));

    CHECK(KM_RESULT_SUCCESS == add_ec_parameters(&req, &param_set));

    CHECK(3 == param_set.len);

    CHECK(KM_TAG_ALGORITHM == param_set.params[1].tag &&
        KM_ALGORITHM_EC == param_set.params[1].integer);

    CHECK(KM_TAG_NO_AUTH_REQUIRED == param_set.params[2].tag &&
        param_set.params[2].boolean);

    ret = TEST_SUCCESS;

cleanup:
    keymaster_free_param_set(&param_set);

    END_TEST(ret);
}

int test_init_key_request(void)
{
    keymaster_key_param_set_t param_set = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("init_key_request");

    // test basic key request (256-AES-GCM)
    set_default_key_request(&req);

    CHECK(KM_RESULT_SUCCESS == init_key_request(&req, &param_set));

    CHECK(7 == param_set.len);

    CHECK(KM_TAG_DIGEST == param_set.params[0].tag &&
        KM_DIGEST_NONE == param_set.params[0].integer);

    CHECK(KM_TAG_KEY_SIZE == param_set.params[1].tag &&
        256 == param_set.params[1].integer);

    CHECK(KM_TAG_ALGORITHM == param_set.params[2].tag &&
        KM_ALGORITHM_AES == param_set.params[2].integer);

    CHECK(KM_TAG_NO_AUTH_REQUIRED == param_set.params[3].tag &&
        param_set.params[3].boolean);

    CHECK(KM_TAG_BLOCK_MODE == param_set.params[4].tag &&
        KM_MODE_GCM == param_set.params[4].integer);

    CHECK(KM_TAG_MIN_MAC_LENGTH == param_set.params[5].tag &&
        128 == param_set.params[5].integer);

    CHECK(KM_TAG_MAC_LENGTH == param_set.params[6].tag &&
        128 == param_set.params[6].integer);

    ret = TEST_SUCCESS;

cleanup:
    keymaster_free_param_set(&param_set);

    END_TEST(ret);
}
