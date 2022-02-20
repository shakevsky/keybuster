#include <sys/system_properties.h>
#include <stdlib.h>
#include <string.h>

#include <skeymaster_log.h>
#include <skeymaster_defs.h>
#include <skeymaster_utils.h>
#include <skeymaster_helper.h>

#define LOG_ERROR(name, ret)   LOGE("%s() failed; ret: %s (%d)", name, km_error_to_string(ret), ret)

KM_Result wait_for_keymaster(void)
{
    KM_Result ret = KM_RESULT_INVALID;
    keymaster_key_param_set_t key_params = {0};
    LOGD("trying to open %s TA", "skeymaster");

    ret = nwd_open_connection();
    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_open_connection", ret);
        goto cleanup;
    }

    ret = nwd_configure(&key_params);
    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_configure", ret);
        goto cleanup;
    }

cleanup:
    return ret;
}

KM_Result generate(key_request_t *req, vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    keymaster_key_param_set_t param_set = {0};
    keymaster_key_characteristics_t characteristics;
    memset(&characteristics, 0, sizeof(characteristics));

    if (KM_RESULT_SUCCESS != init_key_request(req, &param_set)) {
        LOGE("%s failed", "init_key_request");
        goto cleanup;
    }

    print_param_set(&param_set);

    ret = nwd_generate_key(&param_set, ekey, &characteristics);

    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_generate_key", ret);
        goto cleanup;
    }

    print_characteristics(&characteristics);

cleanup:
    keymaster_free_param_set(&param_set);
    keymaster_free_characteristics(&characteristics);
    return ret;
}

KM_Result get_key_characteristics(key_request_t *req, vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    keymaster_key_characteristics_t characteristics;
    memset(&characteristics, 0, sizeof(characteristics));

    ret = nwd_get_key_characteristics(
        ekey, &req->application_id, &req->application_data, &characteristics);

    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_get_key_characteristics", ret);
        goto cleanup;
    }

    print_characteristics(&characteristics);

cleanup:
    keymaster_free_characteristics(&characteristics);
    return ret;
}

KM_Result import(
    key_request_t *req,
    vector_t *key_data,
    vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    keymaster_key_param_set_t param_set = {0};
    keymaster_key_characteristics_t characteristics;
    memset(&characteristics, 0, sizeof(characteristics));

    if (KM_RESULT_SUCCESS != init_key_request(req, &param_set)) {
        LOGE("%s failed", "init_key_request");
        goto cleanup;
    }

    print_param_set(&param_set);

    long key_format = (KM_ALGORITHM_AES != req->algorithm) ? KM_KEY_FORMAT_PKCS8 : KM_KEY_FORMAT_RAW;
    LOGD("key_format: %s (0x%lx)", km_key_format_to_string(key_format), key_format);
    LOGD("algorithm: %s (%d)", km_algorithm_to_string(req->algorithm), req->algorithm);

    ret = nwd_import_key(&param_set, key_format, key_data, ekey, &characteristics);

    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_import_key", ret);
        goto cleanup;
    }

    print_characteristics(&characteristics);

cleanup:
    keymaster_free_param_set(&param_set);
    keymaster_free_characteristics(&characteristics);
    return ret;
}

KM_Result export(key_request_t *req, vector_t *ekey, vector_t *exported)
{
    KM_Result ret = KM_RESULT_INVALID;

    long key_format = (KM_ALGORITHM_AES != req->algorithm) ? KM_KEY_FORMAT_X509 : KM_KEY_FORMAT_RAW;
    LOGD("key_format: %s (0x%lx)", km_key_format_to_string(key_format), key_format);
    LOGD("algorithm: %s (%d)", km_algorithm_to_string(req->algorithm), req->algorithm);

    ret = nwd_export_key(key_format, ekey, &req->application_id, &req->application_data, exported);

    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_export_key", ret);
        goto cleanup;
    }

cleanup:
    return ret;
}

KM_Result upgrade(
    key_request_t *req,
    vector_t *ekey,
    vector_t *new_ekey)
{
    KM_Result ret = KM_RESULT_INVALID;

    keymaster_key_param_set_t param_set = {0};

    if (KM_RESULT_SUCCESS != init_key_request(req, &param_set)) {
        LOGE("%s failed", "init_key_request");
        goto cleanup;
    }

    ret = nwd_upgrade_key(ekey, &param_set, new_ekey);
    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_upgrade_key", ret);
        goto cleanup;
    }

cleanup:
    return ret;
}

KM_Result begin_operation(key_request_t *req, vector_t *ekey, int64_t *operation_handle)
{
    KM_Result ret = KM_RESULT_INVALID;
    keymaster_key_param_set_t param_set = {0};
    keymaster_key_param_set_t out_params = {0};

    if (KM_RESULT_SUCCESS != init_key_request(req, &param_set)) {
        LOGE("%s failed", "init_key_request");
        goto cleanup;
    }

    print_param_set(&param_set);

    ret = nwd_begin(&param_set, req->purpose, ekey, operation_handle, &out_params);
    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_begin", ret);
        goto cleanup;
    }

cleanup:
    keymaster_free_param_set(&param_set);

    return ret;
}

// KM_Result update_operation(
//     uint64_t operation_handle,
//     keymaster_key_param_set_t *update_params,
//     vector_t *ekey,
//     keymaster_key_param_set_t *param_set,
//     keymaster_key_param_set_t *out_params)
// {
//     KM_Result ret = -1;
//     ret = nwd_update(operation_handle, update_params, ekey, application_id, application_data, out_params);
//     if (KM_RESULT_SUCCESS != ret) {
//         LOG_ERROR("nwd_update", ret);
//         goto cleanup;
//     }

//     ret = 0;

// cleanup:
//     return ret;
// }

KM_Result finish_operation(
    int64_t *operation_handle,
    keymaster_key_param_set_t *update_params,
    vector_t *data,
    vector_t *signature,
    vector_t *result)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t output = {0};
    keymaster_key_param_set_t out_params = {0};
    ret = nwd_finish(update_params, data, signature, operation_handle, &output, &out_params);
    if (KM_RESULT_SUCCESS != ret) {
        LOG_ERROR("nwd_finish", ret);
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}

KM_Result do_operation(
    vector_t *data,
    int purpose,
    vector_t *ekey,
    key_request_t *req,
    keymaster_key_param_set_t *begin_params,
    keymaster_key_param_set_t *update_params,
    keymaster_key_param_set_t *out_params)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t result = {0};
    int64_t operation_handle = 0;
    vector_t signature = {0};

    ret = nwd_begin(begin_params, purpose, ekey, &operation_handle, out_params);
    if (KM_RESULT_SUCCESS != ret) {
        goto cleanup;
    }

    ret = finish_operation(&operation_handle, update_params, data, &signature, &result);
    if (KM_RESULT_SUCCESS != ret) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}
