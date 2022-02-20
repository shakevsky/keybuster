#include <test.h>
#include <skeymaster_key_request.h>
#include <skeymaster_utils.h>
#include <skeymaster_commands.h>

int test_generate(void)
{
    vector_t ekey = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("generate");

    set_default_key_request(&req);

    CHECK(KM_RESULT_SUCCESS == generate(&req, &ekey));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}

int test_get_key_characteristics(void)
{
    vector_t ekey = {0};
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("get_key_characteristics");

    set_default_key_request(&req);

    CHECK(KM_RESULT_SUCCESS == generate(&req, &ekey));

    CHECK(KM_RESULT_SUCCESS == get_key_characteristics(&req, &ekey));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}


int test_import(void)
{
    vector_t ekey = {0};
    uint8_t data[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    vector_t key_data = {data, 32};

    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("import");

    set_default_key_request(&req);

    CHECK(KM_RESULT_SUCCESS == import(&req, &key_data, &ekey));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}

int test_export(void)
{
    vector_t ekey = {0};
    uint8_t data[32] = {101, 60, 124, 192, 142, 202, 189, 114, 196, 100, 10, 192, 122, 211, 95, 143, 81, 152, 22, 46, 235, 25, 13, 19, 190, 58, 116, 218, 131, 154, 203, 196};
    vector_t key_data = {data, 32};
    vector_t exported = {0};

    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("export");

    set_default_key_request(&req);
    req.is_exportable = 1;

    CHECK(KM_RESULT_SUCCESS == generate(&req, &ekey));

    CHECK(KM_RESULT_SUCCESS == import(&req, &key_data, &ekey));

    CHECK(KM_RESULT_SUCCESS == export(&req, &ekey, &exported));

    CHECK(0 == memcmp(exported.data, key_data.data, key_data.len));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != exported.data) {
        free(exported.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}

int test_upgrade(void)
{
    vector_t ekey = {0};
    vector_t new_ekey = {0};

    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("upgrade");

    set_default_key_request(&req);

    CHECK(KM_RESULT_SUCCESS == generate(&req, &ekey));

    CHECK(KM_RESULT_SUCCESS == upgrade(&req, &ekey, &new_ekey));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != new_ekey.data) {
        free(new_ekey.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}

int test_begin(void)
{
    vector_t ekey = {0};
    uint8_t nonce[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    int64_t operation_handle = 0;
    key_request_t req;

    int ret = TEST_FAILED;
    BEGIN_TEST("begin");

    set_default_key_request(&req);
    req.purpose = KM_PURPOSE_ENCRYPT;
    req.padding = KM_PAD_NONE;
    req.nonce.data = nonce;
    req.nonce.len = 12;

    CHECK(KM_RESULT_SUCCESS == generate(&req, &ekey));

    CHECK(KM_RESULT_UNSUPPORTED == begin_operation(&req, &ekey, &operation_handle));

    ret = TEST_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    END_TEST(ret);
}
