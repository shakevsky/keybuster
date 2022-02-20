#include <stdlib.h>
#include <string.h>

#include <skeymaster_defs.h>

/*
    Part of the code in this file was inspired (but modified) by AOSP (include/hardware/keymaster_defs.h) in parallel to reverse-engineering
*/

/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


keymaster_tag_type_t keymaster_tag_get_type(keymaster_tag_t tag) {
    return (keymaster_tag_type_t)(tag & (0xF << 28));
}

uint32_t keymaster_tag_mask_type(keymaster_tag_t tag) {
    return tag & 0x0FFFFFFF;
}

keymaster_key_param_t keymaster_param_enum(keymaster_tag_t tag, uint32_t value) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.enumerated = value;
    return param;
}

keymaster_key_param_t keymaster_param_int(keymaster_tag_t tag, uint32_t value) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.integer = value;
    return param;
}

keymaster_key_param_t keymaster_param_long(keymaster_tag_t tag, uint64_t value) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.long_integer = value;
    return param;
}

keymaster_key_param_t keymaster_param_blob(keymaster_tag_t tag, vector_t *blob) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.blob.data = blob->data;
    param.blob.len = blob->len;
    return param;
}

keymaster_key_param_t keymaster_param_bool(keymaster_tag_t tag) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.boolean = true;
    return param;
}

keymaster_key_param_t keymaster_param_date(keymaster_tag_t tag, uint64_t value) {
    keymaster_key_param_t param;
    memset(&param, 0, sizeof(param));
    param.tag = tag;
    param.date_time = value;
    return param;
}

void init_param_set(keymaster_key_param_set_t *param_set, keymaster_key_param_t *key_params, size_t len) {
    param_set->params = malloc(len * sizeof(keymaster_key_param_t));
    if (NULL == param_set->params) {
        return;
    }
    param_set->len = len;

    for (size_t i = 0; i < len; ++i) {
        keymaster_tag_t tag = key_params[i].tag;

        switch (keymaster_tag_get_type(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            param_set->params[i] = keymaster_param_enum(tag, key_params[i].integer);
            break;
        case KM_UINT:
        case KM_UINT_REP:
            param_set->params[i] = keymaster_param_int(tag, key_params[i].integer);
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            param_set->params[i] = keymaster_param_long(tag, key_params[i].long_integer);
            break;
        case KM_DATE:
            param_set->params[i] = keymaster_param_date(tag, key_params[i].date_time);
            break;
        case KM_BOOL:
            if (key_params[i].boolean) {
                param_set->params[i] = keymaster_param_bool(tag);
            }
            else {
                param_set->params[i].tag = KM_TAG_INVALID;
            }
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            param_set->params[i] = keymaster_param_blob(tag, &key_params[i].blob);
            break;
        case KM_INVALID:
        default:
            param_set->params[i].tag = KM_TAG_INVALID;
            break;
        }
    }
}

void keymaster_free_params(keymaster_key_param_t* params, size_t len) {
    for (int i = 0; i < len; ++i) {
        switch (keymaster_tag_get_type(params[i].tag)) {
            case KM_BIGNUM:
            case KM_BYTES:
                free(params[i].blob.data);
                params[i].blob.data = NULL;
                break;
            default:
                break;
        }
    }
    free(params);
}

void keymaster_free_param_set(keymaster_key_param_set_t* param_set) {
    if (NULL != param_set) {
        keymaster_free_params(param_set->params, param_set->len);
        param_set->params = NULL;
        param_set->len = 0;
    }
}

void keymaster_free_characteristics(keymaster_key_characteristics_t *characteristics) {
    if (NULL != characteristics) {
        keymaster_free_param_set(&characteristics->hw_enforced);
        keymaster_free_param_set(&characteristics->sw_enforced);
    }
}

const char *km_result_to_string(KM_Result ret)
{
    switch (ret) {
    case KM_RESULT_SUCCESS:
        return "KM_RESULT_SUCCESS";
    case KM_RESULT_INVALID:
        return "KM_RESULT_INVALID";
    case KM_RESULT_UNSUPPORTED:
        return "KM_RESULT_UNSUPPORTED";
    default:
        return "unknown";
    }
}

const char *km_error_to_string(int error)
{
    switch (error) {
        case KM_ERROR_OK:
            return "KM_ERROR_OK";
        case KM_ERROR_ROOT_OF_TRUST_ALREADY_SET:
            return "KM_ERROR_ROOT_OF_TRUST_ALREADY_SET";
        case KM_ERROR_UNSUPPORTED_PURPOSE:
            return "KM_ERROR_UNSUPPORTED_PURPOSE";
        case KM_ERROR_INCOMPATIBLE_PURPOSE:
            return "KM_ERROR_INCOMPATIBLE_PURPOSE";
        case KM_ERROR_UNSUPPORTED_ALGORITHM:
            return "KM_ERROR_UNSUPPORTED_ALGORITHM";
        case KM_ERROR_INCOMPATIBLE_ALGORITHM:
            return "KM_ERROR_INCOMPATIBLE_ALGORITHM";
        case KM_ERROR_UNSUPPORTED_KEY_SIZE:
            return "KM_ERROR_UNSUPPORTED_KEY_SIZE";
        case KM_ERROR_UNSUPPORTED_BLOCK_MODE:
            return "KM_ERROR_UNSUPPORTED_BLOCK_MODE";
        case KM_ERROR_INCOMPATIBLE_BLOCK_MODE:
            return "KM_ERROR_INCOMPATIBLE_BLOCK_MODE";
        case KM_ERROR_UNSUPPORTED_MAC_LENGTH:
            return "KM_ERROR_UNSUPPORTED_MAC_LENGTH";
        case KM_ERROR_UNSUPPORTED_PADDING_MODE:
            return "KM_ERROR_UNSUPPORTED_PADDING_MODE";
        case KM_ERROR_INCOMPATIBLE_PADDING_MODE:
            return "KM_ERROR_INCOMPATIBLE_PADDING_MODE";
        case KM_ERROR_UNSUPPORTED_DIGEST:
            return "KM_ERROR_UNSUPPORTED_DIGEST";
        case KM_ERROR_INCOMPATIBLE_DIGEST:
            return "KM_ERROR_INCOMPATIBLE_DIGEST";
        case KM_ERROR_INVALID_EXPIRATION_TIME:
            return "KM_ERROR_INVALID_EXPIRATION_TIME";
        case KM_ERROR_INVALID_USER_ID:
            return "KM_ERROR_INVALID_USER_ID";
        case KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT:
            return "KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT";
        case KM_ERROR_UNSUPPORTED_KEY_FORMAT:
            return "KM_ERROR_UNSUPPORTED_KEY_FORMAT";
        case KM_ERROR_INCOMPATIBLE_KEY_FORMAT:
            return "KM_ERROR_INCOMPATIBLE_KEY_FORMAT";
        case KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM:
            return "KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM";
        case KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM:
            return "KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM";
        case KM_ERROR_INVALID_INPUT_LENGTH:
            return "KM_ERROR_INVALID_INPUT_LENGTH";
        case KM_ERROR_KEY_EXPORT_OPTIONS_INVALID:
            return "KM_ERROR_KEY_EXPORT_OPTIONS_INVALID";
        case KM_ERROR_DELEGATION_NOT_ALLOWED:
            return "KM_ERROR_DELEGATION_NOT_ALLOWED";
        case KM_ERROR_KEY_NOT_YET_VALID:
            return "KM_ERROR_KEY_NOT_YET_VALID";
        case KM_ERROR_KEY_EXPIRED:
            return "KM_ERROR_KEY_EXPIRED";
        case KM_ERROR_KEY_USER_NOT_AUTHENTICATED:
            return "KM_ERROR_KEY_USER_NOT_AUTHENTICATED";
        case KM_ERROR_OUTPUT_PARAMETER_NULL:
            return "KM_ERROR_OUTPUT_PARAMETER_NULL";
        case KM_ERROR_INVALID_OPERATION_HANDLE:
            return "KM_ERROR_INVALID_OPERATION_HANDLE";
        case KM_ERROR_INSUFFICIENT_BUFFER_SPACE:
            return "KM_ERROR_INSUFFICIENT_BUFFER_SPACE";
        case KM_ERROR_VERIFICATION_FAILED:
            return "KM_ERROR_VERIFICATION_FAILED";
        case KM_ERROR_TOO_MANY_OPERATIONS:
            return "KM_ERROR_TOO_MANY_OPERATIONS";
        case KM_ERROR_UNEXPECTED_NULL_POINTER:
            return "KM_ERROR_UNEXPECTED_NULL_POINTER";
        case KM_ERROR_INVALID_KEY_BLOB:
            return "KM_ERROR_INVALID_KEY_BLOB";
        case KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED:
            return "KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED";
        case KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED:
            return "KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED";
        case KM_ERROR_IMPORTED_KEY_NOT_SIGNED:
            return "KM_ERROR_IMPORTED_KEY_NOT_SIGNED";
        case KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED:
            return "KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED";
        case KM_ERROR_INVALID_ARGUMENT:
            return "KM_ERROR_INVALID_ARGUMENT";
        case KM_ERROR_UNSUPPORTED_TAG:
            return "KM_ERROR_UNSUPPORTED_TAG";
        case KM_ERROR_INVALID_TAG:
            return "KM_ERROR_INVALID_TAG";
        case KM_ERROR_MEMORY_ALLOCATION_FAILED:
            return "KM_ERROR_MEMORY_ALLOCATION_FAILED";
        case KM_ERROR_INVALID_RESCOPING:
            return "KM_ERROR_INVALID_RESCOPING";
        case KM_ERROR_IMPORT_PARAMETER_MISMATCH:
            return "KM_ERROR_IMPORT_PARAMETER_MISMATCH";
        case KM_ERROR_SECURE_HW_ACCESS_DENIED:
            return "KM_ERROR_SECURE_HW_ACCESS_DENIED";
        case KM_ERROR_OPERATION_CANCELLED:
            return "KM_ERROR_OPERATION_CANCELLED";
        case KM_ERROR_CONCURRENT_ACCESS_CONFLICT:
            return "KM_ERROR_CONCURRENT_ACCESS_CONFLICT";
        case KM_ERROR_SECURE_HW_BUSY:
            return "KM_ERROR_SECURE_HW_BUSY";
        case KM_ERROR_SECURE_HW_COMMUNICATION_FAILED:
            return "KM_ERROR_SECURE_HW_COMMUNICATION_FAILED";
        case KM_ERROR_UNSUPPORTED_EC_FIELD:
            return "KM_ERROR_UNSUPPORTED_EC_FIELD";
        case KM_ERROR_MISSING_NONCE:
            return "KM_ERROR_MISSING_NONCE";
        case KM_ERROR_INVALID_NONCE:
            return "KM_ERROR_INVALID_NONCE";
        case KM_ERROR_MISSING_MAC_LENGTH:
            return "KM_ERROR_MISSING_MAC_LENGTH";
        case KM_ERROR_KEY_RATE_LIMIT_EXCEEDED:
            return "KM_ERROR_KEY_RATE_LIMIT_EXCEEDED";
        case KM_ERROR_CALLER_NONCE_PROHIBITED:
            return "KM_ERROR_CALLER_NONCE_PROHIBITED";
        case KM_ERROR_KEY_MAX_OPS_EXCEEDED:
            return "KM_ERROR_KEY_MAX_OPS_EXCEEDED";
        case KM_ERROR_INVALID_MAC_LENGTH:
            return "KM_ERROR_INVALID_MAC_LENGTH";
        case KM_ERROR_MISSING_MIN_MAC_LENGTH:
            return "KM_ERROR_MISSING_MIN_MAC_LENGTH";
        case KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH:
            return "KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH";
        case KM_ERROR_CANNOT_ATTEST_IDS:
            return "KM_ERROR_CANNOT_ATTEST_IDS";
        case KM_ERROR_DEVICE_LOCKED:
            return "KM_ERROR_DEVICE_LOCKED";
        case KM_ERROR_UNIMPLEMENTED:
            return "KM_ERROR_UNIMPLEMENTED";
        case KM_ERROR_VERSION_MISMATCH:
            return "KM_ERROR_VERSION_MISMATCH";
        case KM_ERROR_UNKNOWN_ERROR:
            return "KM_ERROR_UNKNOWN_ERROR";
        default:
            return km_result_to_string(error);
    }
}

const char *km_key_format_to_string(int key_format)
{
    switch (key_format) {
    case KM_KEY_FORMAT_X509:
        return "KM_KEY_FORMAT_X509";
    case KM_KEY_FORMAT_PKCS8:
        return "KM_KEY_FORMAT_PKCS8";
    case KM_KEY_FORMAT_RAW:
        return "KM_KEY_FORMAT_RAW";
    default:
        return "unknown";
    }
}

const char *km_algorithm_to_string(int algorithm)
{
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return "rsa";
    case KM_ALGORITHM_EC:
        return "ec";
    case KM_ALGORITHM_AES:
        return "aes";
    case KM_ALGORITHM_DES:
        return "des";
    case KM_ALORITHM_HMAC:
        return "hmac";
    default:
        return "unknown";
    }
}

int km_algorithm_to_int(const char *str)
{
    int ret = -1;
    if (0 == strcmp(str, "rsa")) {
        ret = KM_ALGORITHM_RSA;
    }
    else if (0 == strcmp(str, "ec")) {
        ret = KM_ALGORITHM_EC;
    }
    else if (0 == strcmp(str, "aes")) {
        ret = KM_ALGORITHM_AES;
    }
    else if (0 == strcmp(str, "des")) {
        ret = KM_ALGORITHM_DES;
    }
    else if (0 == strcmp(str, "hmac")) {
        ret = KM_ALORITHM_HMAC;
    }
    return ret;
}

int km_purpose_to_int(const char *str)
{
    int ret = -1;
    if (0 == strcmp(str, "encrypt")) {
        ret = KM_PURPOSE_ENCRYPT;
    }
    else if (0 == strcmp(str, "decrypt")) {
        ret = KM_PURPOSE_DECRYPT;
    }
    else if (0 == strcmp(str, "sign")) {
        ret = KM_PURPOSE_SIGN;
    }
    else if (0 == strcmp(str, "verify")) {
        ret = KM_PURPOSE_VERIFY;
    }
    else if (0 == strcmp(str, "wrap_key")) {
        ret = KM_PURPOSE_WRAP_KEY;
    }
    return ret;
}

int km_padding_to_int(const char *str)
{
    int ret = -1;
    if (0 == strcmp(str, "none")) {
        ret = KM_PAD_NONE;
    }
    else if (0 == strcmp(str, "oaep")) {
        ret = KM_PAD_RSA_OAEP;
    }
    else if (0 == strcmp(str, "pss")) {
        ret = KM_PAD_RSA_PSS;
    }
    else if (0 == strcmp(str, "pkcs1.5_encrypt")) {
        ret = KM_PAD_RSA_PKCS1_1_5_ENCRYPT;
    }
    else if (0 == strcmp(str, "pkcs1.5_sign")) {
        ret = KM_PAD_RSA_PKCS1_1_5_SIGN;
    }
    else if (0 == strcmp(str, "pkcs7")) {
        ret = KM_PAD_PKCS7;
    }
    return ret;
}

int km_digest_to_int(const char *str)
{
    int ret = -1;
    if (0 == strcmp(str, "none")) {
        ret = KM_PAD_NONE;
    }
    else if (0 == strcmp(str, "md5")) {
        ret = KM_DIGEST_MD5;
    }
    else if (0 == strcmp(str, "sha1")) {
        ret = KM_DIGEST_SHA1;
    }
    else if (0 == strcmp(str, "sha224")) {
        ret = KM_DIGEST_SHA_2_224;
    }
    else if (0 == strcmp(str, "sha256")) {
        ret = KM_DIGEST_SHA_2_256;
    }
    else if (0 == strcmp(str, "sha384")) {
        ret = KM_DIGEST_SHA_2_384;
    }
    else if (0 == strcmp(str, "sha512")) {
        ret = KM_DIGEST_SHA_2_512;
    }

    return ret;
}
