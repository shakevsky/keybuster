/*
    API from libkeymaster_helper.so (without modifications)
*/
#include <config.h>
#if !defined(KEYMASTER_HELPER_SELF_IMPLEMENTATION)

#include <skeymaster_log.h>
#include <skeymaster_libs.h>
#include <skeymaster_helper.h>

#define LOG_LIB_CALL(name)  LOGD("calling %s from libkeymaster_helper.so - see logs with 'logcat | grep keymaster_tee'", name);


KM_Result nwd_open_connection(void)
{
    LOG_LIB_CALL("nwd_open_connection");
    return g_libkeymaster_helper->nwd_open_connection();
}

KM_Result nwd_configure(keymaster_key_param_set_t *param_set)
{
    LOG_LIB_CALL("nwd_configure");
    return g_libkeymaster_helper->nwd_configure(param_set);
}

KM_Result nwd_generate_key(
    keymaster_key_param_set_t *param_set,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics)
{
    LOG_LIB_CALL("nwd_generate_key");
    return g_libkeymaster_helper->nwd_generate_key(param_set, ekey, characteristics);
}

KM_Result nwd_get_key_characteristics(
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    keymaster_key_characteristics_t * characteristics)
{
    LOG_LIB_CALL("nwd_get_key_characteristics");
    return g_libkeymaster_helper->nwd_get_key_characteristics(
        ekey, application_id, application_data, characteristics);
}

KM_Result nwd_import_key(
    keymaster_key_param_set_t *param_set,
    long key_format,
    vector_t *key_data,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics)
{
    LOG_LIB_CALL("nwd_import_key");
    return g_libkeymaster_helper->nwd_import_key(
        param_set, key_format, key_data, ekey, characteristics);
}

KM_Result nwd_export_key(
    long key_format,
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    vector_t *exported)
{
    LOG_LIB_CALL("nwd_export_key");
    return g_libkeymaster_helper->nwd_export_key(
        key_format, ekey, application_id, application_data, exported);
}

KM_Result nwd_upgrade_key(
    vector_t *ekey,
    keymaster_key_param_set_t *param_set,
    vector_t *new_ekey)
{
    LOG_LIB_CALL("nwd_upgrade_key");
    return g_libkeymaster_helper->nwd_upgrade_key(ekey, param_set, new_ekey);
}

KM_Result nwd_begin(
    keymaster_key_param_set_t *param_set,
    long purpose,
    vector_t *ekey,
    int64_t *operation_handle,
    keymaster_key_param_set_t *out_params)
{
    return KM_RESULT_UNSUPPORTED;
}

KM_Result nwd_finish(
    keymaster_key_param_set_t *param_set,
    vector_t *data,
    vector_t *signature,
    int64_t *operation_handle,
    vector_t *output,
    keymaster_key_param_set_t *output_params)
{
    return KM_RESULT_UNSUPPORTED;
}

#endif // !defined(KEYMASTER_HELPER_SELF_IMPLEMENTATION)
