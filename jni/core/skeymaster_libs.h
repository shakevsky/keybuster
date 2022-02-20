#ifndef _SKEYMASTER_LIBS_H_
#define _SKEYMASTER_LIBS_H_

#include <dlfcn.h>

#include <config.h>
#include <skeymaster_asn1.h>

/** @brief Allocates resources
    @note Must be called before using skeymaster functions
 */
KM_Result initialize_libs(void);

/** @brief Releases resources
 */
void destroy_libs(void);

typedef struct lib_handle_t {
    void *lib;
} lib_handle_t;

/** @brief Exports from libcrypto.so
*/
typedef struct libcrypto_handle_t {
    void *lib;

    ASN1_ITEM *ASN1_INTEGER_it;
    ASN1_ITEM *ASN1_BOOLEAN_it;
    ASN1_ITEM *ASN1_ENUMERATED_it;
    ASN1_ITEM *ASN1_OCTET_STRING_it;

    ASN1_VALUE * (*ASN1_item_new)(const ASN1_ITEM *it);
    void (*ASN1_item_free)(ASN1_VALUE *val, const ASN1_ITEM *it);
    ASN1_VALUE * (*ASN1_item_d2i)(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
    int (*ASN1_item_i2d)(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);

    ASN1_INTEGER * (*ASN1_INTEGER_new)(void);
    void (*ASN1_INTEGER_free)(ASN1_INTEGER *a);
    int (*ASN1_INTEGER_set)(ASN1_INTEGER *a, long v);
    ASN1_INTEGER * (*ASN1_INTEGER_dup)(const ASN1_INTEGER *x);

    ASN1_OCTET_STRING * (*ASN1_OCTET_STRING_new)(void);
    void (*ASN1_OCTET_STRING_free)(ASN1_OCTET_STRING *a);
    int  (*ASN1_OCTET_STRING_set)(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
    ASN1_OCTET_STRING * (*ASN1_OCTET_STRING_dup)(const ASN1_OCTET_STRING *a);

    long (*ASN1_ENUMERATED_get)(const ASN1_ENUMERATED *a);
    int (*ASN1_ENUMERATED_set)(ASN1_ENUMERATED *a, long v);

    _STACK *(*sk_new_null)(void);
    size_t (*sk_push)(_STACK *sk, void *p);
    void *(*sk_delete)(_STACK *sk, size_t where);
    void (*sk_pop_free)(_STACK *st, void(*func)(void *));
    int (*sk_num)(const _STACK *st);
    void *(*sk_value)(const _STACK *st, int i);

    unsigned char *(*SHA256)(const unsigned char *d, size_t n, unsigned char *md);
} libcrypto_handle_t;

/** @brief Exports from libkeymaster_helper.so
*/
typedef struct libkeymaster_helper_t {
    void *lib;

    int (*km_get_ASN1_INTEGER)(ASN1_INTEGER *integer, int32_t *out);
    ASN1_INTEGER *(*km_set_ASN1_INTEGER)(long v);

    int (*km_get_ASN1_INTEGER_BN)(ASN1_INTEGER *integer, int64_t *out);
    ASN1_INTEGER *(*km_set_ASN1_INTEGER_BN)(uint64_t v);

    int (*km_get_ASN1_OCTET_STRING)(ASN1_OCTET_STRING *string, uint8_t **p_out, size_t *p_len);
    ASN1_OCTET_STRING *(*km_set_ASN1_OCTET_STRING)(uint8_t *data, size_t len);

    km_indata_t *(*KM_INDATA_new)(void);
    void (*KM_INDATA_free)(km_indata_t *indata);
    int (*i2d_KM_INDATA)(km_indata_t *indata, uint8_t **out);
    km_indata_t *(*d2i_KM_INDATA)(ASN1_VALUE **val, uint8_t **in, long len);

    km_outdata_t *(*d2i_KM_OUTDATA)(ASN1_VALUE **val, uint8_t **in, long len);
    void (*KM_OUTDATA_free)(km_outdata_t *outdata);

    KM_Result (*nwd_open_connection)(void);

    KM_Result (*nwd_configure)(keymaster_key_param_set_t *param_set);

    KM_Result (*nwd_generate_key)(
        keymaster_key_param_set_t *param_set,
        vector_t *ekey,
        keymaster_key_characteristics_t *characteristics);

    KM_Result (*nwd_get_key_characteristics)(
        vector_t *ekey,
        vector_t *application_id,
        vector_t *application_data,
        keymaster_key_characteristics_t * characteristics);

    KM_Result (*nwd_import_key)(
        keymaster_key_param_set_t *param_set,
        long key_format,
        vector_t *key_data,
        vector_t *ekey,
        keymaster_key_characteristics_t *characteristics);

    KM_Result (*nwd_export_key)(
        long key_format,
        vector_t *ekey,
        vector_t *application_id,
        vector_t *application_data,
        vector_t *exported);

    KM_Result (*nwd_upgrade_key)(
        vector_t *ekey,
        keymaster_key_param_set_t *param_set,
        vector_t *new_ekey);

#ifdef TZOS_TEEGRIS
    int (*get_os_version)(void);
    int (*get_os_patchlevel)(void);
    int (*get_vendor_patchlevel)(void);
#endif // TZOS_TEEGRIS

    int (*km_is_tag_hw)(int tag);
} libkeymaster_helper_t;

/** @brief Load symbol from library handle (dlsym)
*/
#define GET_SYMBOL(handle, name) \
do { \
  handle->name = dlsym(handle->lib, #name); \
  if (NULL == handle->name) { \
    free(handle); \
    handle = NULL; \
    printf("failed to load %s\n", #name); \
    goto cleanup; } \
} while (0)

/** @brief Allocates a handle for the library (dlopen)
    @param[in]      name        Library name
    @param[in]      size        Handle struct size
    @Return         handle      Allocated library handle
*/
void *create_lib_handle(const char *name, size_t size);

/** @brief Allocates a handle for libcrypto.so with the needed symbols
    @Return         handle      Allocated library handle
*/
libcrypto_handle_t *load_libcrypto(void);


/** @brief Allocates a handle for libkeymaster_helper.so with the needed symbols
    @Return         handle      Allocated library handle
*/
libkeymaster_helper_t *load_keymaster_helper(void);

extern libcrypto_handle_t *g_libcrypto;

extern libkeymaster_helper_t *g_libkeymaster_helper;

#endif // _SKEYMASTER_LIBS_H_
