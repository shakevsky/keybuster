#ifndef _SKEYMASTER_HELPER_H_
#define _SKEYMASTER_HELPER_H_

#include <skeymaster_defs.h>
#include <skeymaster_utils.h>

KM_Result nwd_open_connection(void);
KM_Result nwd_close_connection(void);

KM_Result nwd_configure(keymaster_key_param_set_t *param_set);

KM_Result nwd_generate_key(
    keymaster_key_param_set_t *param_set,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics);

KM_Result nwd_get_key_characteristics(
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    keymaster_key_characteristics_t * characteristics);

KM_Result nwd_import_key(
    keymaster_key_param_set_t *param_set,
    long key_format,
    vector_t *key_data,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics);

KM_Result nwd_export_key(
    long key_format,
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    vector_t *exported);

KM_Result nwd_upgrade_key(
    vector_t *ekey,
    keymaster_key_param_set_t *param_set,
    vector_t *new_ekey);

KM_Result nwd_begin(
    keymaster_key_param_set_t *param_set,
    long purpose,
    vector_t *ekey,
    int64_t *operation_handle,
    keymaster_key_param_set_t *out_params);

KM_Result nwd_finish(
    keymaster_key_param_set_t *param_set,
    vector_t *data,
    vector_t *signature,
    int64_t *operation_handle,
    vector_t *output,
    keymaster_key_param_set_t *output_params);

#endif // _SKEYMASTER_HELPER_H_
