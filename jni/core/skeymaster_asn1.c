#include <skeymaster_log.h>
#include <skeymaster_libs.h>
#include <skeymaster_crypto.h>
#include <skeymaster_asn1.h>

#define ASN1_ITYPE_PRIMITIVE    0x0
#define ASN1_ITYPE_SEQUENCE     0x1

#define V_ASN1_SEQUENCE         16

#define ASN1_OP_NEW_PRE     0
#define ASN1_OP_NEW_POST    1
#define ASN1_OP_FREE_PRE    2
#define ASN1_OP_FREE_POST   3
#define ASN1_OP_D2I_PRE     4
#define ASN1_OP_D2I_POST    5
#define ASN1_OP_I2D_PRE     6

/****************************
* ASN1 items/templates/funcs
*****************************/

/** @note Offsets are for 64-bit (Android), commented offsets are used in Keymaster TA
 */

ASN1_TEMPLATE km_param_templates[] = {
    {.flags = 0, .tag = 0, .offset = 0, .field_name = "tag", .item = NULL /*g_libcrypto->ASN1_INTEGER_it*/ },
    {.flags = 0x91, .tag = 0, .offset = 8/*4*/, .field_name = "i", .item = NULL /*g_libcrypto->ASN1_INTEGER_it*/ },
    {.flags = 0x91, .tag = 1, .offset = 0x10/*8*/, .field_name = "b", .item = NULL /*g_libcrypto->ASN1_OCTET_STRING_it*/ }
};

ASN1_AUX km_param_funcs = {NULL, 0, 0, swd_param_cb, 0};

ASN1_ITEM KM_PARAM = {
    .itype = ASN1_ITYPE_SEQUENCE,
    .utype = V_ASN1_SEQUENCE,
    .templates = km_param_templates,
    .tcount = 0x3,
    .funcs = &km_param_funcs,
    .size = 0x1c /*0x10*/,
    .sname = "KM_PARAM"
};

ASN1_TEMPLATE km_key_blob_templates[] = {
    {.flags = 0, .tag = 0, .offset = 0, .field_name = "ver", .item = NULL /*g_libcrypto->ASN1_INTEGER_it*/ },
    {.flags = 0, .tag = 0, .offset = 8/*4*/, .field_name = "key", .item = NULL /*g_libcrypto->ASN1_OCTET_STRING_it*/ },
    {.flags = 0x93, .tag = 0, .offset = 0x10/*8*/, .field_name = "par", .item = &KM_PARAM},
};

ASN1_AUX km_key_blob_funcs = {NULL, 0, 0, swd_key_blob_cb, 0};

ASN1_ITEM KM_KEY_BLOB = {
    .itype = ASN1_ITYPE_SEQUENCE,
    .utype = V_ASN1_SEQUENCE,
    .templates = km_key_blob_templates,
    .tcount = 0x3,
    .funcs = &km_key_blob_funcs,
    .size = 0x18/*0xc*/,
    .sname = "KM_KEY_BLOB"
};

ASN1_TEMPLATE km_ekey_blob_templates[] = {
    {.flags = 0, .tag = 0, .offset = 8/*4*/, .field_name = "enc_ver", .item = NULL /*g_libcrypto->ASN1_INTEGER_it*/ },
    {.flags = 0, .tag = 0, .offset = 0x10/*8*/, .field_name = "ekey", .item = NULL /*g_libcrypto->ASN1_OCTET_STRING_it*/ },
    {.flags = 2, .tag = 0, .offset = 0x18/*0xc*/, .field_name = "enc_par", .item = &KM_PARAM},
};

ASN1_AUX km_ekey_blob_funcs = {NULL, 0, 0, swd_ekey_blob_cb, 0};

ASN1_ITEM KM_EKEY_BLOB = {
    .itype = ASN1_ITYPE_SEQUENCE,
    .utype = V_ASN1_SEQUENCE,
    .templates = km_ekey_blob_templates,
    .tcount = 0x3,
    .funcs = &km_ekey_blob_funcs,
    .size = 0x20/*0x10*/,
    .sname = "KM_EKEY_BLOB"
};

ASN1_TEMPLATE km_root_of_trust_templates[] = {
    {.flags = 0, .tag = 0, .offset = 0, .field_name = "verified_boot_key", .item = NULL /*g_libcrypto->ASN1_OCTET_STRING_it*/ },
    {.flags = 0, .tag = 0, .offset = 8/*4*/, .field_name = "device_locked", .item = NULL /*g_libcrypto->ASN1_BOOLEAN_it*/ },
    {.flags = 0, .tag = 0, .offset = 0x10/*8*/, .field_name = "verified_boot_state", .item = NULL /*g_libcrypto->ASN1_ENUMERATED_it*/ },
    {.flags = 0, .tag = 0, .offset = 0x18/*0xc*/, .field_name = "verified_boot_hash", .item = NULL /*g_libcrypto->ASN1_OCTET_STRING_it*/},
};

ASN1_ITEM KM_ROOT_OF_TRUST = {
    .itype = ASN1_ITYPE_SEQUENCE,
    .utype = V_ASN1_SEQUENCE,
    .templates = km_root_of_trust_templates,
    .tcount = 0x4,
    .funcs = NULL,
    .size = 0x20/*0x10*/,
    .sname = "KM_ROOT_OF_TRUST"
};

void init_asn1_templates(void)
{
    km_param_templates[0].item = g_libcrypto->ASN1_INTEGER_it;
    km_param_templates[1].item = g_libcrypto->ASN1_INTEGER_it;
    km_param_templates[2].item = g_libcrypto->ASN1_OCTET_STRING_it;
    km_key_blob_templates[0].item = g_libcrypto->ASN1_INTEGER_it;
    km_key_blob_templates[1].item = g_libcrypto->ASN1_OCTET_STRING_it;
    km_ekey_blob_templates[0].item = g_libcrypto->ASN1_INTEGER_it;
    km_ekey_blob_templates[1].item = g_libcrypto->ASN1_OCTET_STRING_it;
    km_root_of_trust_templates[0].item = g_libcrypto->ASN1_OCTET_STRING_it;
    km_root_of_trust_templates[1].item = g_libcrypto->ASN1_BOOLEAN_it;
    km_root_of_trust_templates[2].item = g_libcrypto->ASN1_ENUMERATED_it;
    km_root_of_trust_templates[3].item = g_libcrypto->ASN1_OCTET_STRING_it;
}

int swd_param_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    km_param_t *par = (km_param_t *)*in;
    if (ASN1_OP_NEW_POST == operation) {
        par->flags = 0;
        goto cleanup;
    }

    if (ASN1_OP_FREE_PRE != operation || 0 == (par->flags & 2)) {
        goto cleanup;
    }

    ASN1_STRING *value = (ASN1_STRING *)par->b;
    if (NULL == value) {
        value = (ASN1_STRING *)par->i;
    }

    if (0 >= value->length) {
        goto cleanup;
    }

    // if (NULL != value->data && ~value->len >= value->data) {
    //     set_n_bytes_to_zero(value->data, value->length);
    // }

cleanup:
    return 1;
}

int swd_key_blob_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    int ret;

    km_key_blob_t *key_blob = (km_key_blob_t *)*in;
    switch(operation) {
    case ASN1_OP_NEW_POST:
        ret = ASN1_INTEGER_set((ASN1_INTEGER *)key_blob->ver, 2);
        if (0 == ret) {
            LOGE("%s() failed for %s", "ASN1_INTEGER_set", "key_blob->ver");
            goto cleanup;
        }
        break;
    case ASN1_OP_FREE_PRE:
        // if (0 < key_blob->key->length) {
        //     if (NULL != key_blob->key->data && ~key_blob->key->length >= key_blob->key->data) {
        //         set_n_bytes_to_zero(key_blob->key->data, key_blob->key->length)
        //     }
        // }
        ret = 1;
        break;
    case ASN1_OP_FREE_POST:
        break;
    case ASN1_OP_D2I_PRE:
        break;
    case ASN1_OP_D2I_POST:
        // if (0 != km_mark_hidden_tags(key_blob->par)) {
        //     ret = 0;
        //     LOGE("%s failed", "km_mark_hidden_tags");
        //     goto cleanup;
        // }
        break;
    case ASN1_OP_I2D_PRE:
        if (0 != km_del_tags_by_flag(key_blob->par, 1)) {
            ret = 0;
            LOGE("%s failed", "km_del_tags_by_flag");
            goto cleanup;
        }
        break;
    }

    ret = 1;
cleanup:
    return ret;
}

int should_mark_hidden_tag(keymaster_tag_t tag)
{
    switch (tag) {
        case KM_TAG_APPLICATION_ID:
        case KM_TAG_APPLICATION_DATA:
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_MAC_LENGTH:
        case KM_TAG_RESET_SINCE_ID_ROTATION:
        case KM_TAG_EKEY_BLOB_PASSWORD:
            return 1;

        default:
            break;
    }

    /*
        KM_TAG_ATTESTATION_ID_*
        KM_TAG_EKEY_BLOB_*
    */
    if (0x90001451 == tag ||
        (0x900002c6 <= tag && tag < 0x900002ce) ||
        (0x900003e8 <= tag && tag < 0x9000138f)) {
        return 1;
    }

    return 0;
}

int km_mark_hidden_tags(km_param_t * par)
{
    int ret;
    int tag;

    ret = sk_num((_STACK *)par);
    for (int i = 0; i < sk_num((_STACK *)par); ++i) {
        km_param_t *value = (km_param_t *)sk_value((_STACK *)par, i);
        if (NULL == value) {
            ret = -1;
            goto cleanup;
        }

        if (0 != km_get_ASN1_INTEGER(value->tag, &tag)) {
            LOGE("%s() failed for %s", "km_get_ASN1_INTEGER", "param->tag");
            ret = -1;
            goto cleanup;
        }

        if (0 != should_mark_hidden_tag(tag)) {
            value->flags = value->flags | 2;
        }
    }

    ret = 0;

cleanup:
    return ret;
}

int km_del_tags_by_flag(km_param_t *par, int flag)
{
    int ret;

    int num = sk_num((_STACK *)par);
    if (0 >= num) {
        ret = 0;
        goto cleanup;
    }

    for (int i = 0; i < num; ++i) {
        km_param_t *value = (km_param_t *)sk_value((_STACK *)par, i);
        if (NULL == value) {
            ret = -1;
            goto cleanup;
        }

        if (0 != (flag & value->flags)) {
            if (0 == sk_delete((_STACK *)par, i)) {
                ret = -1;
                goto cleanup;
            }

            ASN1_item_free((ASN1_VALUE *)value, (ASN1_ITEM *)&KM_PARAM);
            i = 0;
            if (sk_num((_STACK *)par) < 1) {
                break;
            }
        }
    }

    ret = 0;

cleanup:
    return ret;
}

int swd_ekey_blob_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    int ret;

    if (ASN1_OP_NEW_POST != operation) {
        ret = 1;
        goto cleanup;
    }

    km_ekey_blob_t *ekey = (km_ekey_blob_t *)*in;

    if (0 == ASN1_INTEGER_set(ekey->enc_ver, 0x29)) {
        LOGE("%s failed", "ASN1_INTEGER_set");
        ret = 0;
        goto cleanup;
    }

    ret = 1;

cleanup:

    return ret;
}

/****************************
* ASN1 related functions
*****************************/

int km_get_ASN1_INTEGER(ASN1_INTEGER *integer, int32_t *out)
{
    return g_libkeymaster_helper->km_get_ASN1_INTEGER(integer, out);
}

ASN1_INTEGER *km_set_ASN1_INTEGER(long v)
{
    return g_libkeymaster_helper->km_set_ASN1_INTEGER(v);
}

int km_get_ASN1_INTEGER_BN(ASN1_INTEGER *integer, int64_t *out)
{
    return g_libkeymaster_helper->km_get_ASN1_INTEGER_BN(integer, out);
}

ASN1_INTEGER *km_set_ASN1_INTEGER_BN(uint64_t v)
{
    return g_libkeymaster_helper->km_set_ASN1_INTEGER_BN(v);
}

int km_get_ASN1_OCTET_STRING(ASN1_OCTET_STRING *string, uint8_t **p_out, size_t *p_len)
{
    return g_libkeymaster_helper->km_get_ASN1_OCTET_STRING(string, p_out, p_len);
}

ASN1_OCTET_STRING *km_set_ASN1_OCTET_STRING(uint8_t *data, size_t len)
{
    return g_libkeymaster_helper->km_set_ASN1_OCTET_STRING(data, len);
}

void free_km_param(void *par)
{
    ASN1_item_free((ASN1_VALUE *)par, (ASN1_ITEM *)&KM_PARAM);
}

km_indata_t *KM_INDATA_new(void)
{
    return g_libkeymaster_helper->KM_INDATA_new();
}

void KM_INDATA_free(km_indata_t *indata)
{
    g_libkeymaster_helper->KM_INDATA_free(indata);
}

int i2d_KM_INDATA(km_indata_t *indata, uint8_t **out)
{
    return g_libkeymaster_helper->i2d_KM_INDATA(indata, out);
}

km_indata_t *d2i_KM_INDATA(ASN1_VALUE **val, uint8_t **in, long len)
{
    return g_libkeymaster_helper->d2i_KM_INDATA(val, in, len);
}

km_outdata_t *d2i_KM_OUTDATA(ASN1_VALUE **val, uint8_t **in, long len)
{
    return g_libkeymaster_helper->d2i_KM_OUTDATA(val, in, len);
}

void KM_OUTDATA_free(km_outdata_t *outdata)
{
    g_libkeymaster_helper->KM_OUTDATA_free(outdata);
}

ASN1_OCTET_STRING *encode_ekey_blob(km_ekey_blob_t *ekey_blob)
{
    ASN1_OCTET_STRING *ret = ASN1_OCTET_STRING_new();
    if (NULL == ret) {
        goto cleanup;
    }

    ret->length = ASN1_item_i2d((ASN1_VALUE *)ekey_blob, &ret->data, &KM_EKEY_BLOB);
    if (0 >= ret->length) {
        LOGD("%s failed", "ASN1_item_i2d");
        ASN1_OCTET_STRING_free(ret);
        ret = NULL;
        goto cleanup;
    }

cleanup:
    return ret;
}
