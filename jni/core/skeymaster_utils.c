#include <string.h>
#include <time.h>

#include <skeymaster_log.h>
#include <file_utils.h>
#include <skeymaster_defs.h>
#include <skeymaster_asn1.h>
#include <skeymaster_libs.h>
#include <skeymaster_key_params.h>
#include <skeymaster_api.h>
#include <skeymaster_utils.h>

void free_key_request(key_request_t *req)
{
    if (NULL == req) {
        return;
    }
    if (NULL != req->application_id.data){
        free(req->application_id.data);
    }
    if (NULL != req->application_data.data) {
        free(req->application_data.data);
    }
    if (NULL != req->salt.data) {
        free(req->salt.data);
    }
    if (NULL != req->iv.data) {
        free(req->iv.data);
    }
    if (NULL != req->aad.data) {
        free(req->aad.data);
    }
    if (NULL != req->auth_tag.data) {
        free(req->auth_tag.data);
    }
    if (NULL != req->nonce.data) {
        free(req->nonce.data);
    }
    memset(req, 0, sizeof(key_request_t));
}

const char *cmd_to_usage(const char *cmd)
{
    if (0 == strcmp(cmd, CMD_ATTACK)) {
        return USAGE_ATTACK;
    }
    else if (0 == strcmp(cmd, CMD_GENERATE)) {
        return USAGE_GENERATE;
    }
    else if (0 == strcmp(cmd, CMD_GET_CHARS)) {
        return USAGE_GET_CHARS;
    }
    else if (0 == strcmp(cmd, CMD_IMPORT)) {
        return USAGE_IMPORT;
    }
    else if (0 == strcmp(cmd, CMD_EXPORT)) {
        return USAGE_EXPORT;
    }
    else if (0 == strcmp(cmd, CMD_UPGRADE)) {
        return USAGE_UPGRADE;
    }
    else if (0 == strcmp(cmd, CMD_BEGIN)) {
        return USAGE_BEGIN;
    }
    else {
        return USAGE_DEFAULT;
    }
}

void print_vec(const char *name, const uint8_t *data, size_t len)
{
    if (NULL == data) {
        LOGD("%s: NULL", name);
        return;
    }

    char *hexstring = hexlify(data, len);
    if (NULL == hexstring) {
        LOGE("%s() failed", "hexlify");
        return;
    }
    LOGD("%s: (%s, %ld)", name, hexstring, len);
    free(hexstring);
}

void print_asn1_string(const char *name, const ASN1_STRING *string)
{
    if (NULL == string) {
        LOGD("%s: NULL", name);
        return;
    }

    print_vec(name, string->data, string->length);
}

void print_km_param(const char *name, const km_param_t *par)
{
    int tag;

    if (NULL == par) {
        LOGD("%s->par: NULL", name);
        return;
    }

    for (int i = 0; i < sk_num((_STACK *)par); ++i) {
        km_param_t *value = (km_param_t *)sk_value((_STACK *)par, i);
        if (NULL == value) {
            return;
        }

        if (0 != km_get_ASN1_INTEGER(value->tag, &tag)) {
            LOGE("%s() failed for %s->par->tag", "km_get_ASN1_INTEGER", name);
            return;
        }

        LOGD("%s->par[%d]->tag: 0x%x %s", name, i, tag, get_tag_string(tag));
        print_asn1_string("par->i", value->i);
        print_asn1_string("par->b", value->b);
    }
}

void print_km_indata(const km_indata_t *in)
{
    print_asn1_string("in->ver", in->ver);
    print_asn1_string("in->km_ver", in->km_ver);
    print_asn1_string("in->cmd", in->cmd);
    print_asn1_string("in->pid", in->pid);
    print_asn1_string("in->int0", in->int0);
    print_asn1_string("in->long0", in->long0);
    print_asn1_string("in->long1", in->long1);
    print_asn1_string("in->bin0", in->bin0);
    print_asn1_string("in->bin1", in->bin1);
    print_asn1_string("in->bin2", in->bin2);
    print_asn1_string("in->key", in->key);
    print_km_param("in->par", in->par);
}

void print_km_outdata(const km_outdata_t *out)
{
    print_asn1_string("out->ver", out->ver);
    print_asn1_string("out->cmd", out->cmd);
    print_asn1_string("out->pid", out->pid);
    print_asn1_string("out->err", out->err);
    print_asn1_string("out->int0", out->int0);
    print_asn1_string("out->long0", out->long0);
    print_asn1_string("out->bin0", out->bin0);
    print_asn1_string("out->bin1", out->bin1);
    print_asn1_string("out->bin2", out->bin2);
    print_asn1_string("out->log", out->log);
}

void print_km_key_blob(const km_key_blob_t *key_blob)
{
    print_asn1_string("key_blob->ver", (ASN1_STRING *)key_blob->ver);
    print_asn1_string("key_blob->key", (ASN1_STRING *)key_blob->key);
    print_km_param("key_blob", (km_param_t *)key_blob->par);
}

void print_km_ekey_blob(const km_ekey_blob_t *ekey_blob)
{
    print_asn1_string("ekey_blob->enc_ver", (ASN1_STRING *)ekey_blob->enc_ver);
    print_asn1_string("ekey_blob->ekey", (ASN1_STRING *)ekey_blob->ekey);
    print_km_param("ekey_blob", (km_param_t *)ekey_blob->enc_par);
}

void print_param_set(const keymaster_key_param_set_t *param_set)
{
    if (NULL == param_set || (NULL == param_set->params && 0 == param_set->len)) {
        LOGD("%s", "param_set is NULL");
        return;
    }

    LOGD("param_set->len = %lu", param_set->len);

    char *hexstring = NULL;
    for (int i = 0; i < param_set->len; ++i) {
        keymaster_key_param_t current = param_set->params[i];
        switch (keymaster_tag_get_type(current.tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            LOGD("params[%d] = (tag 0x%x %s, enum %d)",
                i, current.tag, get_tag_string(current.tag), current.enumerated);
            break;
        case KM_UINT:
        case KM_UINT_REP:
            LOGD("params[%d] = (tag 0x%x %s, uint %d)",
                i, current.tag, get_tag_string(current.tag), current.integer);
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            LOGD("params[%d] = (tag 0x%x %s, ulong %ld)",
                i, current.tag, get_tag_string(current.tag), current.long_integer);
            break;
        case KM_DATE:
            LOGD("params[%d] = (tag 0x%x %s, date %ld)",
                i, current.tag, get_tag_string(current.tag), current.date_time);
            break;
        case KM_BOOL:
            LOGD("params[%d] = (tag 0x%x %s, bool %d)",
                i, current.tag, get_tag_string(current.tag), current.boolean);
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            hexstring = hexlify(current.blob.data, current.blob.len);
            if (NULL == hexstring) {
                LOGE("%s() failed", "hexlify");
                break;
            }
            LOGD(
                "params[%d] = (tag 0x%x %s, bytes %s, len %lu)",
                i, current.tag, get_tag_string(current.tag), hexstring, current.blob.len);
            free(hexstring);
            break;
        case KM_INVALID:
        default:
            LOGD("tag 0x%x: invalid", current.tag);
            break;
        }
    }
}

void print_characteristics(const keymaster_key_characteristics_t *characteristics)
{
    if (NULL == characteristics) {
        LOGD("%s", "characteristics is NULL");
        return;
    }

    LOGD("printing &characteristics->%s_enforced", "hw");
    print_param_set(&characteristics->hw_enforced);
    LOGD("printing &characteristics->%s_enforced", "sw");
    print_param_set(&characteristics->sw_enforced);
}

char *hexlify(const uint8_t *data, size_t len)
{
    char *hexstring = NULL;

    if (NULL == data || 0 == len) {
        goto cleanup;
    }

    size_t hex_size = 2 * len * sizeof(*hexstring) + 1;
    if (hex_size < len) {
        goto cleanup;
    }

    hexstring = malloc(hex_size);
    if (NULL == hexstring) {
        goto cleanup;
    }
    memset(hexstring, 0, hex_size);

    char *ptr = hexstring;
    for (size_t i = 0; i < len; ++i) {
        ptr += sprintf(ptr, "%02X", data[i]);
    }
    hexstring[hex_size - 1] = '\0';

cleanup:
    return hexstring;
}

KM_Result copy_vector(vector_t *new, const uint8_t *data, size_t len)
{
    KM_Result ret = KM_RESULT_INVALID;
    if (NULL == new || NULL == data) {
        goto cleanup;
    }

    new->len = len;
    new->data = malloc(len);
    if (NULL == new->data) {
        LOGE("%s failed", "malloc");
        goto cleanup;
    }
    memcpy(new->data, data, len);
    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result replace_tag(km_param_t *par, keymaster_tag_t tag, param_tag_t *param_tag)
{
    KM_Result ret = KM_RESULT_INVALID;
    if (-1 >= km_del_tag(par, tag)) {
        LOGD("%s failed", "km_del_tag");
        goto cleanup;
    }

    if (1 != km_add_tag(par, tag, param_tag, 0)) {
        LOGD("%s failed", "km_add_tag");
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result get_ekey_blob(km_ekey_blob_t **p_ekey_blob, vector_t *ekey)
{
    KM_Result ret = KM_INVALID;
    vector_t copy = {0};
    km_ekey_blob_t *ekey_blob = NULL;

    if (KM_RESULT_SUCCESS != copy_vector(&copy, ekey->data, ekey->len)) {
        goto cleanup;
    }

    ekey_blob = (km_ekey_blob_t *)ASN1_item_d2i(
        NULL, (const uint8_t **)&copy.data, copy.len, &KM_EKEY_BLOB);

    if (0 == ekey_blob) {
        LOGE("%s failed", "ASN1_item_d2i");
        goto cleanup;
    }

    *p_ekey_blob = ekey_blob;

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result print_deserialized_ekey_blob(vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    km_ekey_blob_t *ekey_blob = NULL;

    if (NULL == ekey) {
        goto cleanup;
    }

    print_vec("ekey_blob", ekey->data, ekey->len);

    if (KM_RESULT_SUCCESS != get_ekey_blob(&ekey_blob, ekey)) {
        goto cleanup;
    }

    print_km_ekey_blob(ekey_blob);

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    return ret;
}

KM_Result get_ekey_blob_tag(vector_t *ekey, keymaster_tag_t tag, param_tag_t *param_tag)
{
    KM_Result ret = KM_RESULT_INVALID;
    km_ekey_blob_t *ekey_blob = NULL;

    if (NULL == ekey) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != get_ekey_blob(&ekey_blob, ekey)) {
        goto cleanup;
    }

    if (1 != km_get_tag(ekey_blob->enc_par, tag, 0, param_tag)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    return ret;
}

KM_Result get_ekey_blob_encrypted(vector_t *ekey, vector_t *encrypted)
{
    KM_Result ret = KM_RESULT_INVALID;
    km_ekey_blob_t *ekey_blob = NULL;

    if (NULL == ekey) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != get_ekey_blob(&ekey_blob, ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != copy_vector(encrypted, ekey_blob->ekey->data, ekey_blob->ekey->length)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    return ret;
}

KM_Result save_iv_and_ekey(const char *ekey_path, vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t iv = {0};
    vector_t encrypted = {0};

    if (0 != get_ekey_blob_tag(ekey, KM_TAG_EKEY_BLOB_IV, (param_tag_t *)&iv)) {
        goto cleanup;
    }

    if (0 != get_ekey_blob_encrypted(ekey, &encrypted)) {
        goto cleanup;
    }

    if (0 != save_related_file(ekey_path, "iv-", "", iv.data, iv.len)) {
        LOGE("failed to extract %s", "iv");
        goto cleanup;
    }

    if (0 != save_related_file(ekey_path, "encrypted-", "", encrypted.data, encrypted.len)) {
        LOGE("failed to extract %s", "encrypted");
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != iv.data) {
        free(iv.data);
    }
    if (NULL != encrypted.data) {
        free(encrypted.data);
    }
    return ret;
}

KM_Result parse_asn1(const char *ekey_path)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t ekey = {0};

    if (NULL == ekey_path) {
        LOGE("invalid ekey_path %s (specify -e <path_to_ekey>)", "null");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != prepare_keymaster()) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey_path, &ekey.data, &ekey.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != save_iv_and_ekey(ekey_path, &ekey)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != print_deserialized_ekey_blob(&ekey)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result add_aad_to_ekey(const vector_t *aad, vector_t *ekey)
{
    KM_Result ret = KM_RESULT_INVALID;
    ASN1_OCTET_STRING *changed_ekey = NULL;
    km_ekey_blob_t *ekey_blob = NULL;

    if (NULL == aad || NULL == aad->data || 0 == aad->len) {
        ret = 0;
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != get_ekey_blob(&ekey_blob, ekey)) {
        goto cleanup;
    }

    if (1 != km_add_tag(ekey_blob->enc_par, KM_TAG_ASSOCIATED_DATA, (param_tag_t *)aad, 0)) {
        goto cleanup;
    }

    changed_ekey = encode_ekey_blob(ekey_blob);
    free(ekey->data);
    if (KM_RESULT_SUCCESS != copy_vector(ekey, changed_ekey->data, changed_ekey->length)) {
        LOGE("%s failed", "copy_vector");
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != changed_ekey) {
        ASN1_OCTET_STRING_free(changed_ekey);
    }
    if (NULL != ekey_blob) {
        ASN1_item_free((ASN1_VALUE *)ekey_blob, &KM_EKEY_BLOB);
    }

    return ret;
}

KM_Result init_basic_param_set(
    vector_t *application_id,
    vector_t *application_data,
    keymaster_key_param_set_t *param_set)
{
    KM_Result ret = KM_RESULT_INVALID;
    param_set->len = 0;

    if (NULL != application_id && 0 != application_id->len &&
        0 != add_blob_to_param_set(param_set, KM_TAG_APPLICATION_ID, application_id)) {
        LOGE("failed to add %s", "application_id");
        goto cleanup;
    }

    if (NULL != application_data && 0 != application_data->len &&
        0 != add_blob_to_param_set(param_set, KM_TAG_APPLICATION_DATA, application_data)) {
        LOGE("failed to add %s", "application_data");
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (KM_RESULT_SUCCESS != ret) {
        keymaster_free_param_set(param_set);
    }
    return ret;
}

KM_Result add_aes_parameters(key_request_t *req, keymaster_key_param_set_t *param_set)
{
    KM_Result ret = KM_RESULT_INVALID;
    if (NULL == param_set->params) {
        goto cleanup;
    }

    if (0 != add_int_to_param_set(param_set, KM_TAG_ALGORITHM, KM_ALGORITHM_AES)) {
        goto cleanup;
    }

    if (0 != add_bool_to_param_set(param_set, KM_TAG_NO_AUTH_REQUIRED)) {
        goto cleanup;
    }

    if (KM_MODE_GCM == req->mode) {
        if (0 != add_int_to_param_set(param_set, KM_TAG_BLOCK_MODE, KM_MODE_GCM)) {
            goto cleanup;
        }
        if (0 != add_int_to_param_set(param_set, KM_TAG_MIN_MAC_LENGTH, 128)) {
            goto cleanup;
        }
        if (0 != add_int_to_param_set(param_set, KM_TAG_MAC_LENGTH, 128)) {
            goto cleanup;
        }
    }
    else {
        if (0 != add_int_to_param_set(param_set, KM_TAG_BLOCK_MODE, KM_MODE_ECB)) {
            goto cleanup;
        }
        if (0 != add_int_to_param_set(param_set, KM_TAG_BLOCK_MODE, KM_MODE_CBC)) {
            goto cleanup;
        }
        if (0 != add_int_to_param_set(param_set, KM_TAG_BLOCK_MODE, KM_MODE_CTR)) {
            goto cleanup;
        }
    }

    if (NULL != req->nonce.data && 0 != add_blob_to_param_set(param_set, KM_TAG_NONCE, &req->nonce)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result add_rsa_parameters(key_request_t *req, keymaster_key_param_set_t *param_set)
{
    KM_Result ret = KM_RESULT_INVALID;
    if (NULL == param_set->params) {
        goto cleanup;
    }

    if (0 != add_int_to_param_set(param_set, KM_TAG_ALGORITHM, KM_ALGORITHM_RSA)) {
        goto cleanup;
    }

    if (0 != add_bool_to_param_set(param_set, KM_TAG_NO_AUTH_REQUIRED)) {
        goto cleanup;
    }

    // keymaster supports only 3 or 0x10001
    if (0 != add_int_to_param_set(param_set, KM_TAG_RSA_PUBLIC_EXPONENT, req->public_exponent)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result add_ec_parameters(key_request_t *req, keymaster_key_param_set_t *param_set)
{
    KM_Result ret = KM_RESULT_INVALID;
    if (NULL == param_set->params) {
        goto cleanup;
    }

    if (0 != add_int_to_param_set(param_set, KM_TAG_ALGORITHM, KM_ALGORITHM_EC)) {
        goto cleanup;
    }

    if (0 != add_bool_to_param_set(param_set, KM_TAG_NO_AUTH_REQUIRED)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

KM_Result init_key_request(
    key_request_t *req,
    keymaster_key_param_set_t *param_set)
{
    KM_Result ret = KM_RESULT_INVALID;

    if (KM_RESULT_SUCCESS != init_basic_param_set(&req->application_id, &req->application_data, param_set)) {
        goto cleanup;
    }

    if (NULL != req->aad.data && 0 != add_blob_to_param_set(param_set, KM_TAG_ASSOCIATED_DATA, &req->aad)) {
        LOGE("failed to add %s", "aad");
        goto cleanup;
    }

    if (NULL != req->iv.data && 0 != add_blob_to_param_set(param_set, KM_TAG_EKEY_BLOB_IV, &req->iv)) {
        LOGE("failed to add %s", "iv");
        goto cleanup;
    }

    if (NULL != req->hek_randomness.data && 0 != add_blob_to_param_set(param_set, KM_TAG_EKEY_BLOB_HEK_RANDOMNESS, &req->hek_randomness)) {
        LOGE("failed to add %s", "aad");
        goto cleanup;
    }

    if (0 != req->is_plain && 0 != add_int_to_param_set(param_set, KM_TAG_EKEY_IS_KEY_BLOB_PLAIN, req->is_plain)) {
        LOGE("failed to add %s", "is_plain");
        goto cleanup;
    }

    if (0 != req->is_exportable && 0 != add_bool_to_param_set(param_set, KM_TAG_EXPORTABLE)) {
        LOGE("failed to add %s", "KM_TAG_EXPORTABLE");
        goto cleanup;
    }

    if (-1 != req->enc_ver && 0 != add_int_to_param_set(param_set, KM_TAG_EKEY_BLOB_ENC_VER, req->enc_ver)) {
        LOGE("failed to add %s", "KM_TAG_EKEY_BLOB_ENC_VER");
        goto cleanup;
    }

    if (-1 != req->purpose && 0 != add_int_to_param_set(param_set, KM_TAG_PURPOSE, req->purpose)) {
        LOGE("failed to add %s", "KM_TAG_PURPOSE");
        goto cleanup;
    }

    if (-1 != req->padding && 0 != add_int_to_param_set(param_set, KM_TAG_PADDING, req->padding)) {
        LOGE("failed to add %s", "KM_TAG_PADDING");
        goto cleanup;
    }

    if (-1 != req->digest && 0 != add_int_to_param_set(param_set, KM_TAG_DIGEST, req->digest)) {
        LOGE("failed to add %s", "KM_TAG_DIGEST");
        goto cleanup;
    }

    if (0 != req->key_size && 0 != add_int_to_param_set(param_set, KM_TAG_KEY_SIZE, req->key_size)) {
        goto cleanup;
    }

    switch (req->algorithm) {
        case KM_ALGORITHM_AES:
            ret = add_aes_parameters(req, param_set);
            break;

        case KM_ALGORITHM_RSA:
            ret = add_rsa_parameters(req, param_set);
            break;

        case KM_ALGORITHM_EC:
            ret = add_ec_parameters(req, param_set);
            break;

        default:
            ret = KM_RESULT_UNSUPPORTED;
            break;
    }

cleanup:
    return ret;
}
