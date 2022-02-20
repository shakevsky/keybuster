#include <string.h>

#include <skeymaster_log.h>
#include <file_utils.h>
#include <skeymaster_defs.h>
#include <skeymaster_libs.h>
#include <skeymaster_utils.h>
#include <skeymaster_commands.h>
#include <skeymaster_helper.h>
#include <skeymaster_api.h>

KM_Result prepare_keymaster(void)
{
    KM_Result ret = wait_for_keymaster();
    if (KM_RESULT_SUCCESS != ret) {
        LOGE("failed to get keymaster; ret: %d", ret);
        goto cleanup;
    }

    LOGD("%s", "keymaster is ready");

cleanup:
    return ret;
}

KM_Result do_generate(key_request_t *req, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", "null");
        goto cleanup;
    }

    if (NULL == req) {
        LOGE("invalid req is %s", "null");
        goto cleanup;
    }

    if (0 == req->key_size) {
        LOGE("invalid req->key_size %d (specify --key-size <size>)", 0);
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != generate(req, &ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != save_iv_and_ekey(ekey_path, &ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != WRITE_FILE(ekey_path, ekey.data, ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != print_deserialized_ekey_blob(&ekey)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

    LOGD("successfully called %s", "generateKey");

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    return ret;
}

KM_Result do_get_characteristics(key_request_t *req, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", "null");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey_path, &ekey.data, &ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != print_deserialized_ekey_blob(&ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != add_aad_to_ekey(&req->aad, &ekey)) {
        LOGE("failed to add %s to ekey", "aad");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != get_key_characteristics(req, &ekey)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

    LOGD("successfully called %s", "getKeyCharacteristics");

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    return ret;
}

KM_Result do_import(key_request_t *req, const char *key_path, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};
    vector_t key_data;

    if (NULL == key_path) {
        LOGE("invalid key_path %s (specify -p <path_to_key>)", key_path);
        goto cleanup;
    }

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", ekey_path);
        goto cleanup;
    }

    if (0 == req->key_size) {
        LOGE("invalid req->key_size %d (specify --key-size <size>)", 0);
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(key_path, &key_data.data, &key_data.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != import(req, &key_data, &ekey)) {
        LOGE("%s failed", "import");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != WRITE_FILE(ekey_path, ekey.data, ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != save_iv_and_ekey(ekey_path, &ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != print_deserialized_ekey_blob(&ekey)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

    LOGD("successfully called %s", "importKey");

cleanup:
    if (NULL != key_data.data) {
        free(key_data.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    return ret;
}

KM_Result do_export(key_request_t *req, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};
    vector_t exported = {0};

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", ekey_path);
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey_path, &ekey.data, &ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != add_aad_to_ekey(&req->aad, &ekey)) {
        LOGE("failed to add %s to ekey", "aad");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != export(req, &ekey, &exported)) {
        goto cleanup;
    }

    print_vec("exported", exported.data, exported.len);

    const char *prefix = (KM_ALGORITHM_RSA == req->algorithm) ? "public-" : "plain-";

    if (0 != save_related_file(ekey_path, prefix, "", exported.data, exported.len)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

    LOGD("successfully called %s", "exportKey");

cleanup:
    if (NULL != exported.data) {
        free(exported.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    return ret;
}

KM_Result do_upgrade(key_request_t *req, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};
    vector_t new_ekey = {0};

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", ekey_path);
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey_path, &ekey.data, &ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != upgrade(req, &ekey, &new_ekey)) {
        goto cleanup;
    }

    if (NULL == new_ekey.data) {
        LOGD("%s did not change new_ekey", "upgrade");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != save_related_file(ekey_path, "upgraded-", "", new_ekey.data, new_ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != print_deserialized_ekey_blob(&new_ekey)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

    LOGD("successfully called %s", "upgradeKey");

cleanup:
    if (NULL != new_ekey.data) {
        free(new_ekey.data);
    }
    if (NULL != ekey.data) {
        free(ekey.data);
    }
    return ret;
}

KM_Result do_begin(key_request_t *req, const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};
    int64_t operation_handle = 0;

    if (-1 == req->algorithm) {
        LOGE("invalid algorithm %d (specify --algorithm [aes|rsa|ec|hmac])", req->algorithm);
        goto cleanup;
    }

    if (-1 == req->purpose) {
        LOGE("invalid purpose %d (specify --purpose [encrypt|decrypt|sign|verify|wrap_key])", req->purpose);
        goto cleanup;
    }

    if (-1 == req->padding) {
        LOGE("invalid padding %d (specify --padding none)", req->padding);
        goto cleanup;
    }

    if (NULL == req->nonce.data) {
        LOGE("invalid nonce %p (specify --nonce nonce.bin)", req->nonce.data);
        goto cleanup;
    }

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s", ekey_path);
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey_path, &ekey.data, &ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != begin_operation(req, &ekey, &operation_handle)) {
        LOGE("%s failed", "begin");
        goto cleanup;
    }

    LOGI("operation handle: %lx", operation_handle);
    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != ekey.data) {
        free(ekey.data);
    }

    return ret;
}
