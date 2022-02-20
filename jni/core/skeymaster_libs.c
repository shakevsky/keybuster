#include <stdlib.h>
#include <string.h>

#include <config.h>
#include <skeymaster_log.h>
#include <skeymaster_libs.h>

libcrypto_handle_t *g_libcrypto = NULL;

libkeymaster_helper_t *g_libkeymaster_helper = NULL;

#ifdef USE_LIBTEECL
libteecl_handle_t *g_libteecl = NULL;
#endif  // USE_LIBTEECL

#ifdef TZOS_KINIBI
#include <libmcclient.h>
#endif // TZOS_KINIBI

KM_Result initialize_libs(void)
{
    KM_Result ret = KM_RESULT_INVALID;
    LOGD("initializing libs %s", "[libscrypto, libkeymaster_helper, libteecl, libMcClient]");
    g_libcrypto = load_libcrypto();
    if (NULL == g_libcrypto) {
        goto cleanup;
    }

    init_asn1_templates();

    LOGD("%s successfully loaded", "libcrypto");

    g_libkeymaster_helper = load_keymaster_helper();
    if (NULL == g_libkeymaster_helper) {
        goto cleanup;
    }

    LOGD("%s successfully loaded", "libkeymaster_helper");

#ifdef USE_LIBTEECL
    g_libteecl = load_libteecl();
    if (NULL == g_libteecl) {
        goto cleanup;
    }

    LOGD("%s successfully loaded", "libteecl");
#endif  // USE_LIBTEECL

#ifdef TZOS_KINIBI
    g_libMcClient = load_libMcClient();
    if (NULL == g_libMcClient) {
        goto cleanup;
    }
    LOGD("%s successfully loaded", "libMcClient");
#endif // TZOS_KINIBI

    ret = KM_RESULT_SUCCESS;

cleanup:
    return ret;
}

void destroy_libs(void) {
    free(g_libcrypto);
    g_libcrypto = NULL;

    free(g_libkeymaster_helper);
    g_libkeymaster_helper = NULL;

#ifdef USE_LIBTEECL
    free(g_libteecl);
    g_libteecl = NULL;
#endif  // USE_LIBTEECL

#ifdef TZOS_KINIBI
    free(g_libMcClient);
    g_libMcClient = NULL;
#endif  // TZOS_KINIBI
}

void *create_lib_handle(const char *name, size_t size)
{
    lib_handle_t *handle = malloc(size);
    if (NULL == handle) {
        LOGE("failed to allocate handle %s\n", name);
        goto cleanup;
    }

    memset(handle, 0, size);

    handle->lib = dlopen(name, RTLD_NOW);
    if (NULL == handle->lib) {
        LOGE("failed to dlopen %s\n", name);
        free(handle);
        handle = NULL;
        goto cleanup;
    }

cleanup:
    return handle;
}

libcrypto_handle_t *load_libcrypto(void)
{
    libcrypto_handle_t *handle = create_lib_handle("libcrypto.so", sizeof(libcrypto_handle_t));

    if (NULL == handle) {
        goto cleanup;
    }

    GET_SYMBOL(handle, ASN1_INTEGER_it);
    GET_SYMBOL(handle, ASN1_BOOLEAN_it);
    GET_SYMBOL(handle, ASN1_ENUMERATED_it);
    GET_SYMBOL(handle, ASN1_OCTET_STRING_it);
    GET_SYMBOL(handle, ASN1_item_new);
    GET_SYMBOL(handle, ASN1_item_free);
    GET_SYMBOL(handle, ASN1_item_d2i);
    GET_SYMBOL(handle, ASN1_item_i2d);
    GET_SYMBOL(handle, ASN1_INTEGER_new);
    GET_SYMBOL(handle, ASN1_INTEGER_free);
    GET_SYMBOL(handle, ASN1_INTEGER_set);
    GET_SYMBOL(handle, ASN1_INTEGER_dup);
    GET_SYMBOL(handle, ASN1_OCTET_STRING_new);
    GET_SYMBOL(handle, ASN1_OCTET_STRING_free);
    GET_SYMBOL(handle, ASN1_OCTET_STRING_set);
    GET_SYMBOL(handle, ASN1_OCTET_STRING_dup);
    GET_SYMBOL(handle, ASN1_ENUMERATED_get);
    GET_SYMBOL(handle, ASN1_ENUMERATED_set);
    GET_SYMBOL(handle, sk_new_null);
    GET_SYMBOL(handle, sk_push);
    GET_SYMBOL(handle, sk_delete);
    GET_SYMBOL(handle, sk_pop_free);
    GET_SYMBOL(handle, sk_num);
    GET_SYMBOL(handle, sk_value);
    GET_SYMBOL(handle, SHA256);

cleanup:
    return handle;
}

libkeymaster_helper_t *load_keymaster_helper(void)
{
    libkeymaster_helper_t *handle = create_lib_handle("libkeymaster_helper.so", sizeof(libkeymaster_helper_t));

    if (NULL == handle) {
        goto cleanup;
    }

    GET_SYMBOL(handle, km_get_ASN1_INTEGER);
    GET_SYMBOL(handle, km_get_ASN1_INTEGER_BN);
    GET_SYMBOL(handle, km_get_ASN1_OCTET_STRING);
    GET_SYMBOL(handle, km_set_ASN1_INTEGER);
    GET_SYMBOL(handle, km_set_ASN1_INTEGER_BN);
    GET_SYMBOL(handle, km_set_ASN1_OCTET_STRING);
    GET_SYMBOL(handle, KM_INDATA_new);
    GET_SYMBOL(handle, KM_INDATA_free);
    GET_SYMBOL(handle, i2d_KM_INDATA);
    GET_SYMBOL(handle, d2i_KM_INDATA);
    GET_SYMBOL(handle, d2i_KM_OUTDATA);
    GET_SYMBOL(handle, KM_OUTDATA_free);
    GET_SYMBOL(handle, nwd_open_connection);
    GET_SYMBOL(handle, nwd_configure);
    GET_SYMBOL(handle, nwd_generate_key);
    GET_SYMBOL(handle, nwd_get_key_characteristics);
    GET_SYMBOL(handle, nwd_import_key);
    GET_SYMBOL(handle, nwd_export_key);
    GET_SYMBOL(handle, nwd_upgrade_key);
#ifdef TZOS_TEEGRIS
    GET_SYMBOL(handle, get_os_version);
    GET_SYMBOL(handle, get_os_patchlevel);
    GET_SYMBOL(handle, get_vendor_patchlevel);
#endif // TZOS_TEEGRIS
    GET_SYMBOL(handle, km_is_tag_hw);

cleanup:
    return handle;
}
