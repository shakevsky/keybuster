#include <string.h>

#include <skeymaster_log.h>
#include <skeymaster_defs.h>
#include <skeymaster_asn1.h>
#include <skeymaster_libs.h>
#include <skeymaster_key_params.h>

int is_repeatable_tag(keymaster_tag_t tag) {
    switch (keymaster_tag_get_type(tag)) {
        case KM_UINT_REP:
        case KM_ENUM_REP:
        case KM_ULONG_REP:
            return 0;
            break;
        default:
            return -1;
    }
}

int km_push_param(
    km_param_t *par,
    keymaster_tag_t tag,
    ASN1_INTEGER *integer,
    ASN1_OCTET_STRING *string,
    int flags)
{
    int ret;

    if (NULL == par) {
        LOGE("%s is NULL", "par");
        ret = -1;
        goto cleanup;
    }

    km_param_t *new_par = (km_param_t *)ASN1_item_new((ASN1_ITEM *)&KM_PARAM);
    if (NULL == new_par) {
        LOGE("%s failed", "sKM_PARAM_new");
        ret = -1;
        goto cleanup;
    }

    new_par->i = integer;
    new_par->b = string;
    new_par->flags = flags;
    if (0 == ASN1_INTEGER_set(new_par->tag, tag)) {
        LOGE("%s failed for %x", "ASN1_INTEGER_set", tag);
        ASN1_item_free((ASN1_VALUE *)new_par, &KM_PARAM);
        ret = -1;
        goto cleanup;
    }

    if (0 == sk_push((_STACK *)par, new_par)) {
        ASN1_item_free((ASN1_VALUE *)new_par, &KM_PARAM);
        ret = -1;
        goto cleanup;
    }

    ret = 1;

cleanup:
    return ret;
}

int km_get_tag(km_param_t *par, keymaster_tag_t tag, int tag_count, param_tag_t *param_tag)
{
    int count = 0;
    int num = sk_num((_STACK *)par);
    if (NULL == par || 1 > num) {
        goto cleanup;
    }

    keymaster_tag_type_t tag_type = keymaster_tag_get_type(tag);

    for (int i = 0; i < num; ++i) {
        km_param_t *current = (km_param_t *)sk_value((_STACK *)par, i);

        if (NULL == current) {
            LOGE("%s returned NULL", "sk_value");
            goto error;
        }

        int current_tag = 0;
        if (0 != km_get_ASN1_INTEGER(current->tag, &current_tag)) {
            LOGE("%s failed for tag %p", "km_get_ASN1_INTEGER", current->tag);
            goto error;
        }

        if (tag != current_tag) {
            continue;
        }

        ++count;

        if (count != tag_count + 1 || NULL == param_tag) {
            continue;
        }

        switch (tag_type) {
        case KM_ENUM:
        case KM_ENUM_REP:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&param_tag->enumerated)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", tag);
                goto error;
            }
            break;
        case KM_UINT:
        case KM_UINT_REP:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&param_tag->integer)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", tag);
                goto error;
            }
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            if (0 != km_get_ASN1_INTEGER_BN(current->i, (int64_t *)&param_tag->long_integer)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER_BN", tag);
                goto error;
            }
            break;
        case KM_DATE:
            if (0 != km_get_ASN1_INTEGER_BN(current->i, (int64_t *)&param_tag->date_time)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER_BN", tag);
                goto error;
            }
            break;
        case KM_BOOL:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&param_tag->boolean) ||
                (int)param_tag->boolean > 2) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", tag);
                goto error;
            }
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            if (0 != param_tag->blob.len && current->b->length > param_tag->blob.len) {
                LOGE("overflow: try to write %d bytes in %lu buffer", current->b->length, param_tag->blob.len);
                goto error;
            }
            if (0 != km_get_ASN1_OCTET_STRING(current->b, &param_tag->blob.data, &param_tag->blob.len)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_OCTET_STRING", tag);
                goto error;
            }
            break;
        case KM_INVALID:
        default:
            LOGD("tag %x: invalid", tag);
            break;
        }
    }

    if (1 < count && -1 == is_repeatable_tag(tag)) {
        LOGE("multiple non repetable tag: %x", tag);
        goto error;
    }

cleanup:
    return count;

error:
    return -1;
}

int km_is_tag_value_exist(km_param_t *par, keymaster_tag_t tag, param_tag_t *ref_tag)
{

    int ret = km_get_tag(par, tag, 0, NULL);
    if (0 >= ret) {
        goto cleanup;
    }

    int tag_count = ret;

    for (int i = 0; i < tag_count; ++i) {
        keymaster_tag_type_t tag_type = keymaster_tag_get_type(tag);
        param_tag_t current_param_tag;
        memset(&current_param_tag, 0, sizeof(current_param_tag));

        ret = km_get_tag(par, tag, i, &current_param_tag);
        if (ret <= 0 && (KM_BIGNUM == tag_type || KM_BYTES == tag_type)) {
            free(current_param_tag.blob.data);
        }

        if (0 > ret) {
            goto cleanup;
        }
        else if (0 == ret) {
            continue;
        }

        switch (tag_type) {
        case KM_ENUM:
        case KM_ENUM_REP:
            ret = ref_tag->enumerated - current_param_tag.enumerated;
            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }
            break;
        case KM_UINT:
        case KM_UINT_REP:
            ret = ref_tag->integer - current_param_tag.integer;
            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            ret = memcmp(&current_param_tag, ref_tag, 8);
            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }
            break;
        case KM_DATE:
            ret = memcmp(&current_param_tag, ref_tag, 8);
            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }
            break;
        case KM_BOOL:
            ret = ref_tag->boolean - current_param_tag.boolean;
            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            ret = -1;
            if (NULL != ref_tag && NULL != current_param_tag.blob.data &&
                current_param_tag.blob.len == ref_tag->blob.len && 0 != ref_tag->blob.len) {
                ret = memcmp(current_param_tag.blob.data, ref_tag->blob.data, ref_tag->blob.len);
            }

            if (NULL != current_param_tag.blob.data) {
                free(current_param_tag.blob.data);
            }

            if (0 == ret) {
                ret = 1;
                goto cleanup;
            }

            break;
        case KM_INVALID:
        default:
            LOGD("tag %x: invalid", tag);
            break;
        }
    }

    ret = 0;

cleanup:
    return ret;
}

int km_add_tag(km_param_t *par, keymaster_tag_t tag, param_tag_t *param_tag, int flags)
{
    int ret;
    ASN1_INTEGER *integer = NULL;
    ASN1_OCTET_STRING *string = NULL;

    if (NULL == par || NULL == param_tag) {
        LOGE("%s", "invalid arguments par/param_tag");
        ret = -1;
        goto cleanup;
    }

    if (0 != km_is_tag_value_exist(par, tag, param_tag)) {
        ret = 0;
        goto cleanup;
    }

    ret = km_get_tag(par, tag, 0, NULL);
    if (0 > ret) {
        LOGE("%s failed", "km_get_tag");
        ret = -1;
        goto cleanup;
    }

    if (0 != ret && -1 == is_repeatable_tag(tag)) {
        LOGW("non repetable tag %x already exists with different value", tag);
        goto cleanup;
    }

    switch (keymaster_tag_get_type(tag)) {
    case KM_ENUM:
    case KM_ENUM_REP:
        integer = km_set_ASN1_INTEGER(param_tag->enumerated);
        if (NULL == integer) {
            LOGE("%s failed for %x", "km_set_ASN1_INTEGER", tag);
            ret = -1;
            goto cleanup;
        }
        break;
    case KM_UINT:
    case KM_UINT_REP:
        integer = km_set_ASN1_INTEGER(param_tag->integer);
        if (NULL == integer) {
            LOGE("%s failed for %x", "km_set_ASN1_INTEGER", tag);
            ret = -1;
            goto cleanup;
        }
        break;
    case KM_ULONG:
    case KM_ULONG_REP:
        integer = km_set_ASN1_INTEGER_BN(param_tag->long_integer);
        if (NULL == integer) {
            LOGE("%s failed for %x", "km_set_ASN1_INTEGER", tag);
            ret = -1;
            goto cleanup;
        }
        break;
    case KM_DATE:
        integer = km_set_ASN1_INTEGER_BN(param_tag->date_time);
        if (NULL == integer) {
            LOGE("%s failed for %x", "km_set_ASN1_INTEGER", tag);
            ret = -1;
            goto cleanup;
        }
        break;
    case KM_BOOL:
        integer = km_set_ASN1_INTEGER(param_tag->boolean);
        if (NULL == integer) {
            LOGE("%s failed for %x", "ASN1_INTEGER_set", tag);
            ret = -1;
            goto cleanup;
        }
        break;
    case KM_BIGNUM:
    case KM_BYTES:
        /*
            Omit length check
        */
        // if (0x2001 <= param_tag->blob.len) {
        //     LOGD("blob too long: %lu > 0x2000", param_tag->blob.len);
        //     ret = -1;
        //     goto cleanup;
        // }
        string = km_set_ASN1_OCTET_STRING(param_tag->blob.data, param_tag->blob.len);
        if (NULL == string) {
            LOGE("%s failed for %x", "km_set_ASN1_OCTET_STRING", tag);
        }
        break;
    case KM_INVALID:
    default:
        LOGD("tag %x: invalid", tag);
        break;
    }

    ret = km_push_param(par, tag, integer, string, flags);

    if (-1 == ret) {
        ASN1_INTEGER_free(integer);
        ASN1_OCTET_STRING_free(string);
    }

cleanup:
    return ret;
}

int km_del_tag(km_param_t *par, keymaster_tag_t tag)
{
    int ret = sk_num((_STACK *)par);
    for (int i = 0; i < ret; ++i) {
        while( true ) {
            km_param_t *current = (km_param_t *)sk_value((_STACK *)par, i);
            if (NULL == current) {
                ret = -1;
                goto cleanup;
            }

            int current_tag = 0;
            if (0 != km_get_ASN1_INTEGER(current->tag, &current_tag)) {
                LOGE("%s() failed for %x", "km_get_ASN1_INTEGER", tag);
                ret = -1;
                goto cleanup;
            }

            if (current_tag != tag) {
                break;
            }

            if (NULL == sk_delete((_STACK *)par, i)) {
                LOGE("%s failed", "sk_KM_PARAM_delete");
                ret = -1;
                goto cleanup;
            }

            ASN1_item_free((ASN1_VALUE *)current, &KM_PARAM);
            i = 0;
            ret = sk_num((_STACK *)par);
            if (1 > ret) {
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

// km_param_t *km_param_set_to_asn1(keymaster_key_param_set_t *param_set)
// {
//     return g_libkeymaster_helper->km_param_set_to_asn1(param_set);
// }

km_param_t * km_param_set_to_asn1(keymaster_key_param_set_t *param_set)
{
    param_tag_t *param_tag = NULL;

    km_param_t *par = (km_param_t *)sk_new_null();
    if (NULL == par) {
        LOGE("%s() failed", "sk_KM_PARAM_new_null");
        goto cleanup;
    }

    for (int i = 0; i < param_set->len; ++i) {
        switch (keymaster_tag_get_type(param_set->params[i].tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            param_tag = (param_tag_t *)&param_set->params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            param_tag = (param_tag_t *)&param_set->params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            param_tag = (param_tag_t *)&param_set->params[i].long_integer;
            break;
        case KM_DATE:
            param_tag = (param_tag_t *)&param_set->params[i].date_time;
            break;
        case KM_BOOL:
            param_tag = (param_tag_t *)&param_set->params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            param_tag = (param_tag_t *)&param_set->params[i].blob;
            break;
        case KM_INVALID:
        default:
            LOGE("tag %x: invalid", param_set->params[i].tag);
            goto error;
            break;
        }

        if (1 > km_add_tag(par, param_set->params[i].tag, param_tag, 0)) {
            LOGE("%s failed for tag %x", "km_add_tag", param_set->params[i].tag);
            goto error;
        }
    }

cleanup:
    return (km_param_t *)par;

error:
    sk_pop_free((_STACK *)par, free_km_param);
    par = NULL;
    goto cleanup;
}

int km_param_set_from_asn1(km_param_t *par, keymaster_key_param_set_t *param_set)
{
    int ret;
    keymaster_key_param_t *params = NULL;

    if (NULL == par){
        LOGW("%s is NULL", "par");
        ret = 0;
        param_set->params = NULL;
        param_set->len = 0;
        goto cleanup;
    }

    int num = sk_num((_STACK *)par);
    if (100 < num) {
        LOGE("%s() failed", "sk_KM_PARAM_num()");
        ret = -1;
        goto cleanup;
    }

    if (0 == num) {
        ret = 0;
        LOGW("%s is 0", "sk_num(par)");
        param_set->params = NULL;
        param_set->len = 0;
        goto cleanup;
    }

    params = malloc(num * sizeof(keymaster_key_param_t));
    if (NULL == params) {
        ret = -1;
        goto cleanup;
    }

    memset(params, 0, num * sizeof(keymaster_key_param_t));

    for (int i = 0; i < num; ++i) {
        km_param_t *current = (km_param_t *)sk_value((_STACK *)par, i);

        if (NULL == current) {
            goto error;
        }

        if (0 != km_get_ASN1_INTEGER(current->tag, (int32_t *)&params[i].tag)) {
            LOGE("%s failed for tag %p", "km_get_ASN1_INTEGER", current->tag);
            goto error;
        }

        switch (keymaster_tag_get_type(params[i].tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&params[i].enumerated)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, enum %d)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].enumerated);
            break;
        case KM_UINT:
        case KM_UINT_REP:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&params[i].integer)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, uint %d)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].integer);
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            if (0 != km_get_ASN1_INTEGER_BN(current->i, (int64_t *)&params[i].long_integer)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER_BN", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, ulong %ld)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].long_integer);
            break;
        case KM_DATE:
            if (0 != km_get_ASN1_INTEGER_BN(current->i, (int64_t *)&params[i].date_time)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER_BN", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, date %ld)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].date_time);
            break;
        case KM_BOOL:
            if (0 != km_get_ASN1_INTEGER(current->i, (int32_t *)&params[i].boolean) ||
                (int)params[i].boolean > 2) {
                LOGE("%s failed for tag %x", "km_get_ASN1_INTEGER", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, bool %d)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].boolean);
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            if (0 != km_get_ASN1_OCTET_STRING(current->b, &params[i].blob.data, &params[i].blob.len)) {
                LOGE("%s failed for tag %x", "km_get_ASN1_OCTET_STRING", params[i].tag);
                goto error;
            }

            LOGD("params[%d] = (tag 0x%x %s, bytes %s, len %lu)",
                i, params[i].tag, get_tag_string(params[i].tag), params[i].blob.data, params[i].blob.len);
            break;
        case KM_INVALID:
        default:
            LOGE("tag %x: invalid", params[i].tag);
            break;
        }
    }

    ret = 0;
    param_set->params = params;
    param_set->len = num;

cleanup:
    return ret;

error:
    keymaster_free_params(params, num);
    free(params);
    return -1;
}

int is_tag_in_key_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag)
{
    int ret;
    if (0 == param_set->len) {
        ret = 1;
        goto cleanup;
    }

    for (int i = 0; i < param_set->len; ++i) {
        if (tag == param_set->params[i].tag) {
            ret = 0;
            LOGD("0x%x tag is already in param set", tag);
            goto cleanup;
        }
    }

    LOGD("0x%x tag not in param set", tag);

    ret = -1;

cleanup:
    return ret;
}

int add_key_parameter_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag)
{
    int ret;
    void *temp = realloc(param_set->params, (param_set->len + 1) * sizeof(keymaster_key_param_t));

    if (NULL == temp) {
        LOGE("failed to add %x tag to param set", tag);
        ret = -1;
        goto cleanup;
    }

    param_set->params = temp;
    param_set->params[param_set->len].tag = tag;
    param_set->len = param_set->len + 1;

    ret = 0;

cleanup:
    return ret;
}

int add_int_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, int value)
{
    int ret = add_key_parameter_to_param_set(param_set, tag);

    if (0 != ret) {
        goto cleanup;
    }

    param_set->params[param_set->len - 1].integer = value;

cleanup:
    return ret;
}

int add_date_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, uint64_t value)
{
    int ret = add_key_parameter_to_param_set(param_set, tag);

    if (0 != ret) {
        goto cleanup;
    }

    param_set->params[param_set->len - 1].date_time = value;

cleanup:
    return ret;
}

int add_bool_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag)
{
    int ret = add_key_parameter_to_param_set(param_set, tag);

    if (0 != ret) {
        goto cleanup;
    }

    param_set->params[param_set->len - 1].boolean = true;

cleanup:
    return ret;
}

int add_blob_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, vector_t *value)
{
    vector_t copy = {0};
    int ret = add_key_parameter_to_param_set(param_set, tag);

    if (0 != ret) {
        goto cleanup;
    }

    copy.len = value->len;
    copy.data = malloc(value->len);
    if (NULL == copy.data) {
        LOGE("%s failed", "malloc");
        ret = -2;
        goto cleanup;
    }

    memcpy(copy.data, value->data, value->len);

    LOGD("copy.data %p, copy.len %lu", copy.data, copy.len);

    param_set->params[param_set->len - 1] = keymaster_param_blob(tag, &copy);

cleanup:
    return ret;
}

char *get_tag_string(keymaster_tag_t tag)
{
    switch(tag) {
        case KM_TAG_INVALID:
            return "KM_TAG_INVALID";
        case KM_TAG_PURPOSE:
            return "KM_TAG_PURPOSE";
        case KM_TAG_ALGORITHM:
            return "KM_TAG_ALGORITHM";
        case KM_TAG_KEY_SIZE:
            return "KM_TAG_KEY_SIZE";
        case KM_TAG_BLOCK_MODE:
            return "KM_TAG_BLOCK_MODE";
        case KM_TAG_DIGEST:
            return "KM_TAG_DIGEST";
        case KM_TAG_PADDING:
            return "KM_TAG_PADDING";
        case KM_TAG_CALLER_NONCE:
            return "KM_TAG_CALLER_NONCE";
        case KM_TAG_MIN_MAC_LENGTH:
            return "KM_TAG_MIN_MAC_LENGTH";
        case KM_TAG_EC_CURVE:
            return "KM_TAG_EC_CURVE";
        case KM_TAG_RSA_PUBLIC_EXPONENT:
            return "KM_TAG_RSA_PUBLIC_EXPONENT";
        case KM_TAG_INCLUDE_UNIQUE_ID:
            return "KM_TAG_INCLUDE_UNIQUE_ID";
        case KM_TAG_BLOB_USAGE_REQUIREMENTS:
            return "KM_TAG_BLOB_USAGE_REQUIREMENTS";
        case KM_TAG_BOOTLOADER_ONLY:
            return "KM_TAG_BOOTLOADER_ONLY";
        case KM_TAG_ROLLBACK_RESISTANCE:
            return "KM_TAG_ROLLBACK_RESISTANCE";
        case KM_TAG_HARDWARE_TYPE:
            return "KM_TAG_HARDWARE_TYPE";
        case KM_TAG_ACTIVE_DATETIME:
            return "KM_TAG_ACTIVE_DATETIME";
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
            return "KM_TAG_ORIGINATION_EXPIRE_DATETIME";
        case KM_TAG_USAGE_EXPIRE_DATETIME:
            return "KM_TAG_USAGE_EXPIRE_DATETIME";
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
            return "KM_TAG_MIN_SECONDS_BETWEEN_OPS";
        case KM_TAG_MAX_USES_PER_BOOT:
            return "KM_TAG_MAX_USES_PER_BOOT";
        case KM_TAG_USER_ID:
            return "KM_TAG_USER_ID";
        case KM_TAG_USER_SECURE_ID:
            return "KM_TAG_USER_SECURE_ID";
        case KM_TAG_NO_AUTH_REQUIRED:
            return "KM_TAG_NO_AUTH_REQUIRED";
        case KM_TAG_USER_AUTH_TYPE:
            return "KM_TAG_USER_AUTH_TYPE";
        case KM_TAG_AUTH_TIMEOUT:
            return "KM_TAG_AUTH_TIMEOUT";
        case KM_TAG_ALLOW_WHILE_ON_BODY:
            return "KM_TAG_ALLOW_WHILE_ON_BODY";
        case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED:
            return "KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED";
        case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED:
            return "KM_TAG_TRUSTED_CONFIRMATION_REQUIRED";
        case KM_TAG_UNLOCKED_DEVICE_REQUIRED:
            return "KM_TAG_UNLOCKED_DEVICE_REQUIRED";
        case KM_TAG_APPLICATION_ID:
            return "KM_TAG_APPLICATION_ID";
        case KM_TAG_APPLICATION_DATA:
            return "KM_TAG_APPLICATION_DATA";
        case KM_TAG_CREATION_DATETIME:
            return "KM_TAG_CREATION_DATETIME";
        case KM_TAG_ORIGIN:
            return "KM_TAG_ORIGIN";
        case KM_TAG_ROOT_OF_TRUST:
            return "KM_TAG_ROOT_OF_TRUST";
        case KM_TAG_OS_VERSION:
            return "KM_TAG_OS_VERSION";
        case KM_TAG_OS_PATCHLEVEL:
            return "KM_TAG_OS_PATCHLEVEL";
        case KM_TAG_UNIQUE_ID:
            return "KM_TAG_UNIQUE_ID";
        case KM_TAG_ATTESTATION_CHALLENGE:
            return "KM_TAG_ATTESTATION_CHALLENGE";
        case KM_TAG_ATTESTATION_APPLICATION_ID:
            return "KM_TAG_ATTESTATION_APPLICATION_ID";
        case KM_TAG_ATTESTATION_ID_BRAND:
            return "KM_TAG_ATTESTATION_ID_BRAND";
        case KM_TAG_ATTESTATION_ID_DEVICE:
            return "KM_TAG_ATTESTATION_ID_DEVICE";
        case KM_TAG_ATTESTATION_ID_PRODUCT:
            return "KM_TAG_ATTESTATION_ID_PRODUCT";
        case KM_TAG_ATTESTATION_ID_SERIAL:
            return "KM_TAG_ATTESTATION_ID_SERIAL";
        case KM_TAG_ATTESTATION_ID_IMEI:
            return "KM_TAG_ATTESTATION_ID_IMEI";
        case KM_TAG_ATTESTATION_ID_MEID:
            return "KM_TAG_ATTESTATION_ID_MEID";
        case KM_TAG_ATTESTATION_ID_MANUFACTURER:
            return "KM_TAG_ATTESTATION_ID_MANUFACTURER";
        case KM_TAG_ATTESTATION_ID_MODEL:
            return "KM_TAG_ATTESTATION_ID_MODEL";
        case KM_TAG_VENDOR_PATCHLEVEL:
            return "KM_TAG_VENDOR_PATCHLEVEL";
        case KM_TAG_BOOT_PATCHLEVEL:
            return "KM_TAG_BOOT_PATCHLEVEL";
        case KM_TAG_ASSOCIATED_DATA:
            return "KM_TAG_ASSOCIATED_DATA";
        case KM_TAG_NONCE:
            return "KM_TAG_NONCE";
        case KM_TAG_MAC_LENGTH:
            return "KM_TAG_MAC_LENGTH";
        case KM_TAG_RESET_SINCE_ID_ROTATION:
            return "KM_TAG_RESET_SINCE_ID_ROTATION";
        case KM_TAG_CONFIRMATION_TOKEN:
            return "KM_TAG_CONFIRMATION_TOKEN";
        case KM_TAG_EKEY_BLOB_IV:
            return "KM_TAG_EKEY_BLOB_IV";
        case KM_TAG_EKEY_BLOB_AUTH_TAG:
            return "KM_TAG_EKEY_BLOB_AUTH_TAG";
        case KM_TAG_EKEY_BLOB_DO_UPGRADE:
            return "KM_TAG_EKEY_BLOB_DO_UPGRADE";
        case KM_TAG_EKEY_BLOB_PASSWORD:
            return "KM_TAG_EKEY_BLOB_PASSWORD";
        case KM_TAG_EKEY_BLOB_SALT:
            return "KM_TAG_EKEY_BLOB_SALT";
        case KM_TAG_EKEY_BLOB_ENC_VER:
            return "KM_TAG_EKEY_BLOB_ENC_VER";
        case KM_TAG_EKEY_IS_KEY_BLOB_PLAIN:
            return "KM_TAG_EKEY_IS_KEY_BLOB_PLAIN";
        case KM_TAG_EKEY_BLOB_HEK_RANDOMNESS:
            return "KM_TAG_EKEY_BLOB_HEK_RANDOMNESS";
        case KM_TAG_INTEGRITY_FLAGS:
            return "KM_TAG_INTEGRITY_FLAGS";
        case KM_TAG_EXPORTABLE:
            return "KM_TAG_EXPORTABLE";
        case KM_TAG_ORIGIN_2:
            return "KM_TAG_ORIGIN_2";
        default:
            return "Unknown";
    }
}
