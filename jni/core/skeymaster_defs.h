#ifndef _SKEYMASTER_DEFS_H_
#define _SKEYMASTER_DEFS_H_

#include <stdbool.h>
#include <stdint.h>

#include <skeymaster_status.h>

// Algorithm values.
typedef enum KM_ALGORITHM {
    KM_ALGORITHM_RSA    = 0x01,
    KM_ALGORITHM_EC     = 0x03,
    KM_ALGORITHM_AES    = 0x20,
    KM_ALGORITHM_DES    = 0x21,
    KM_ALORITHM_HMAC    = 0x80
} KM_ALGORITHM;

// Block modes.
typedef enum KM_MODE {
    KM_MODE_ECB = 0x01,
    KM_MODE_CBC = 0x02,
    KM_MODE_CTR = 0x03,
    KM_MODE_GCM = 0x20
} KM_MODE;

// Padding modes.
typedef enum KM_PADDING {
    KM_PAD_NONE                     = 0x01,
    KM_PAD_RSA_OAEP                 = 0x02,
    KM_PAD_RSA_PSS                  = 0x03,
    KM_PAD_RSA_PKCS1_1_5_ENCRYPT    = 0x04,
    KM_PAD_RSA_PKCS1_1_5_SIGN       = 0x05,
    KM_PAD_PKCS7                    = 0x40
} KM_PADDING;

typedef enum OPENSSL_PADDING {
    OPENSSL_PAD_NONE                = 0x03,
    OPENSSL_PAD_OAEP                = 0x04,
    OPENSSL_PAD_PKCS1_1_5           = 0x01,
    OPENSSL_PAD_PSS                 = 0x06,
    OPENSSL_PAD_UNKNOWN             = 0x00
} OPENSSL_PADDING;

// Digest modes.
typedef enum KM_DIGEST {
    KM_DIGEST_NONE          = 0,
    KM_DIGEST_MD5           = 1,
    KM_DIGEST_SHA1          = 2,
    KM_DIGEST_SHA_2_224     = 3,
    KM_DIGEST_SHA_2_256     = 4,
    KM_DIGEST_SHA_2_384     = 5,
    KM_DIGEST_SHA_2_512     = 6
} KM_DIGEST;

// Key origins.
typedef enum KM_ORIGIN {
    KM_ORIGIN_GENERATED = 0,
    KM_ORIGIN_IMPORTED = 2,
    KM_ORIGIN_UNKNOWN = 3,
    KM_ORIGIN_SECURELY_IMPORTED = 4
} KM_ORIGIN;

// Key usability requirements.
typedef enum KM_BLOB {
    KM_BLOB_STANDALONE = 0,
    KM_BLOB_REQUIRES_FILE_SYSTEM = 1
} KM_BLOB;

// Operation Purposes.
typedef enum KM_PURPOSE {
    KM_PURPOSE_ENCRYPT  = 0x01, // 0x01
    KM_PURPOSE_DECRYPT  = 0x02, // 0x02
    KM_PURPOSE_SIGN     = 0x03, // 0x04
    KM_PURPOSE_VERIFY   = 0x04, // 0x08
    KM_PURPOSE_WRAP_KEY = 0x05  // 0x32
} KM_PURPOSE;

// Key formats.
typedef enum KM_KEY_FORMAT {
    KM_KEY_FORMAT_X509  = 0,
    KM_KEY_FORMAT_PKCS8 = 1,
    KM_KEY_FORMAT_RAW   = 3
} KM_KEY_FORMAT;

// User authenticators.
typedef enum HW_AUTH {
    HW_AUTH_PASSWORD = 1 << 0,
    HW_AUTH_BIOMETRIC = 1 << 1
} HW_AUTH;

typedef enum keymaster_tag_type_t {
    KM_INVALID = 0 << 28,
    KM_ENUM = 1 << 28,
    KM_ENUM_REP = 2 << 28,
    KM_UINT = 3 << 28,
    KM_UINT_REP = 4 << 28,
    KM_ULONG = 5 << 28,
    KM_DATE = 6 << 28,
    KM_BOOL = 7 << 28,
    KM_BIGNUM = 8 << 28,
    KM_BYTES = 9 << 28,
    KM_ULONG_REP = 10 << 28
} keymaster_tag_type_t;

typedef enum keymaster_tag_t {
    KM_TAG_INVALID = 0x0,                                   // KM_INVALID | 0
    KM_TAG_PURPOSE = 0x20000001,                            // KM_ENUM_REP | 1
    KM_TAG_ALGORITHM = 0x10000002,                          // KM_ENUM | 2
    KM_TAG_KEY_SIZE = 0x30000003,                           // KM_UINT | 3
    KM_TAG_BLOCK_MODE = 0x20000004,                         // KM_ENUM_REP | 4
    KM_TAG_DIGEST = 0x20000005,                             // KM_ENUM_REP | 5
    KM_TAG_PADDING = 0x20000006,                            // KM_ENUM_REP | 6
    KM_TAG_CALLER_NONCE = 0x70000007,                       // KM_BOOL | 7
    KM_TAG_MIN_MAC_LENGTH = 0x30000008,                     // KM_UINT | 8
    // Tag 9 reserved
    KM_TAG_EC_CURVE = 0x1000000a,                           // KM_ENUM | 10
    KM_TAG_RSA_PUBLIC_EXPONENT = 0x500000c8,                // KM_ULONG | 200
    // Tag 201 reserved
    KM_TAG_INCLUDE_UNIQUE_ID = 0x700000ca,                  // KM_BOOL | 202
    KM_TAG_BLOB_USAGE_REQUIREMENTS = 0x1000012d,            // KM_ENUM | 301
    KM_TAG_BOOTLOADER_ONLY = 0x7000012e,                    // KM_BOOL | 302
    KM_TAG_ROLLBACK_RESISTANCE = 0x7000012f,                // KM_BOOL | 303
    // Reserved for future use.
    KM_TAG_HARDWARE_TYPE = 0x10000130,                      // KM_ENUM | 304
    KM_TAG_ACTIVE_DATETIME = 0x60000190,                    // KM_DATE | 400
    KM_TAG_ORIGINATION_EXPIRE_DATETIME = 0x60000191,        // KM_DATE | 401
    KM_TAG_USAGE_EXPIRE_DATETIME = 0x60000192,              // KM_DATE | 402
    KM_TAG_MIN_SECONDS_BETWEEN_OPS = 0x30000193,            // KM_UINT | 403
    KM_TAG_MAX_USES_PER_BOOT = 0x30000194,                  // KM_UINT | 404
    KM_TAG_USER_ID = 0x300001f5,                            // KM_UINT | 501
    KM_TAG_USER_SECURE_ID = 0xa00001f6,                     // KM_ULONG_REP | 502
    KM_TAG_NO_AUTH_REQUIRED = 0x700001f7,                   // KM_BOOL | 503
    KM_TAG_USER_AUTH_TYPE = 0x100001f8,                     // KM_ENUM | 504
    KM_TAG_AUTH_TIMEOUT = 0x300001f9,                       // KM_UINT | 505
    KM_TAG_ALLOW_WHILE_ON_BODY = 0x700001fa,                // KM_BOOL | 506
    KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 0x700001fb,     // KM_BOOL | 507
    KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 0x700001fc,      // KM_BOOL | 508
    KM_TAG_UNLOCKED_DEVICE_REQUIRED = 0x700001fd,           // KM_BOOL | 509
    KM_TAG_APPLICATION_ID = 0x90000259,                     // KM_BYTES | 601
    KM_TAG_APPLICATION_DATA = 0x900002bc,                   // KM_BYTES | 700
    KM_TAG_CREATION_DATETIME = 0x600002bd,                  // KM_DATE | 701
    KM_TAG_ORIGIN = 0x100002c0,                             // KM_ENUM | 702
    KM_TAG_ROOT_OF_TRUST = 0x900002c0,                      // KM_BYTES | 704
    KM_TAG_OS_VERSION = 0x300002c1,                         // KM_UINT | 705
    KM_TAG_OS_PATCHLEVEL = 0x300002c2,                      // KM_UINT | 706
    KM_TAG_UNIQUE_ID = 0x900002c3,                          // KM_BYTES | 707
    KM_TAG_ATTESTATION_CHALLENGE = 0x900002c4,              // KM_BYTES | 708
    KM_TAG_ATTESTATION_APPLICATION_ID = 0x900002c5,         // KM_BYTES | 709
    KM_TAG_ATTESTATION_ID_BRAND = 0x900002c6,               // KM_BYTES | 710
    KM_TAG_ATTESTATION_ID_DEVICE = 0x900002c7,              // KM_BYTES | 711
    KM_TAG_ATTESTATION_ID_PRODUCT = 0x900002c8,             // KM_BYTES | 712
    KM_TAG_ATTESTATION_ID_SERIAL = 0x900002c9,              // KM_BYTES | 713
    KM_TAG_ATTESTATION_ID_IMEI = 0x900002ca,                // KM_BYTES | 714
    KM_TAG_ATTESTATION_ID_MEID = 0x900002cb,                // KM_BYTES | 715
    KM_TAG_ATTESTATION_ID_MANUFACTURER = 0x900002cc,        // KM_BYTES | 716
    KM_TAG_ATTESTATION_ID_MODEL = 0x900002cd,               // KM_BYTES | 717
    KM_TAG_VENDOR_PATCHLEVEL = 0x300002ce,                  // KM_UINT | 718
    KM_TAG_BOOT_PATCHLEVEL = 0x300002cf,                    // KM_UINT | 719
    KM_TAG_ASSOCIATED_DATA = 0x900003e8,                    // KM_BYTES | 1000
    KM_TAG_NONCE = 0x900003e9,                              // KM_BYTES | 1001
    KM_TAG_MAC_LENGTH = 0x300003eb,                         // KM_UINT | 1003
    KM_TAG_RESET_SINCE_ID_ROTATION = 0x700003ec,            // KM_BOOL | 1004
    KM_TAG_CONFIRMATION_TOKEN = 0x900003ed,                 // KM_BYTES | 1005
    KM_TAG_EKEY_BLOB_IV = 0x90001388,
    KM_TAG_EKEY_BLOB_AUTH_TAG = 0x90001389,
    KM_TAG_EKEY_BLOB_DO_UPGRADE = 0x3000138d,
    KM_TAG_EKEY_BLOB_PASSWORD = 0x9000138e,
    KM_TAG_EKEY_BLOB_SALT = 0x9000138f,
    KM_TAG_EKEY_BLOB_ENC_VER = 0x30001390,
    KM_TAG_EKEY_IS_KEY_BLOB_PLAIN = 0x30001391,
    KM_TAG_EKEY_BLOB_HEK_RANDOMNESS = 0x90001392,
    KM_TAG_INTEGRITY_FLAGS = 0x300013a7,
    KM_TAG_EXPORTABLE = 0x7000025a,
    KM_TAG_ORIGIN_2 = 0x100002be
} keymaster_tag_t;

typedef enum KM_ERROR {
    KM_ERROR_OK = 0,
    KM_ERROR_ROOT_OF_TRUST_ALREADY_SET = -1,
    KM_ERROR_UNSUPPORTED_PURPOSE = -2,
    KM_ERROR_INCOMPATIBLE_PURPOSE = -3,
    KM_ERROR_UNSUPPORTED_ALGORITHM = -4,
    KM_ERROR_INCOMPATIBLE_ALGORITHM = -5,
    KM_ERROR_UNSUPPORTED_KEY_SIZE = -6,
    KM_ERROR_UNSUPPORTED_BLOCK_MODE = -7,
    KM_ERROR_INCOMPATIBLE_BLOCK_MODE = -8,
    KM_ERROR_UNSUPPORTED_MAC_LENGTH = -9,
    KM_ERROR_UNSUPPORTED_PADDING_MODE = -10,
    KM_ERROR_INCOMPATIBLE_PADDING_MODE = -11,
    KM_ERROR_UNSUPPORTED_DIGEST = -12,
    KM_ERROR_INCOMPATIBLE_DIGEST = -13,
    KM_ERROR_INVALID_EXPIRATION_TIME = -14,
    KM_ERROR_INVALID_USER_ID = -15,
    KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT = -16,
    KM_ERROR_UNSUPPORTED_KEY_FORMAT = -17,
    KM_ERROR_INCOMPATIBLE_KEY_FORMAT = -18,
    KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19,
    KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20,
    KM_ERROR_INVALID_INPUT_LENGTH = -21,
    KM_ERROR_KEY_EXPORT_OPTIONS_INVALID = -22,
    KM_ERROR_DELEGATION_NOT_ALLOWED = -23,
    KM_ERROR_KEY_NOT_YET_VALID = -24,
    KM_ERROR_KEY_EXPIRED = -25,
    KM_ERROR_KEY_USER_NOT_AUTHENTICATED = -26,
    KM_ERROR_OUTPUT_PARAMETER_NULL = -27,
    KM_ERROR_INVALID_OPERATION_HANDLE = -28,
    KM_ERROR_INSUFFICIENT_BUFFER_SPACE = -29,
    KM_ERROR_VERIFICATION_FAILED = -30,
    KM_ERROR_TOO_MANY_OPERATIONS = -31,
    KM_ERROR_UNEXPECTED_NULL_POINTER = -32,
    KM_ERROR_INVALID_KEY_BLOB = -33,
    KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED = -34,
    KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED = -35,
    KM_ERROR_IMPORTED_KEY_NOT_SIGNED = -36,
    KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED = -37,
    KM_ERROR_INVALID_ARGUMENT = -38,
    KM_ERROR_UNSUPPORTED_TAG = -39,
    KM_ERROR_INVALID_TAG = -40,
    KM_ERROR_MEMORY_ALLOCATION_FAILED = -41,
    KM_ERROR_INVALID_RESCOPING = -42,
    KM_ERROR_IMPORT_PARAMETER_MISMATCH = -44,
    KM_ERROR_SECURE_HW_ACCESS_DENIED = -45,
    KM_ERROR_OPERATION_CANCELLED = -46,
    KM_ERROR_CONCURRENT_ACCESS_CONFLICT = -47,
    KM_ERROR_SECURE_HW_BUSY = -48,
    KM_ERROR_SECURE_HW_COMMUNICATION_FAILED = -49,
    KM_ERROR_UNSUPPORTED_EC_FIELD = -50,
    KM_ERROR_MISSING_NONCE = -51,
    KM_ERROR_INVALID_NONCE = -52,
    KM_ERROR_MISSING_MAC_LENGTH = -53,
    KM_ERROR_KEY_RATE_LIMIT_EXCEEDED = -54,
    KM_ERROR_CALLER_NONCE_PROHIBITED = -55,
    KM_ERROR_KEY_MAX_OPS_EXCEEDED = -56,
    KM_ERROR_INVALID_MAC_LENGTH = -57,
    KM_ERROR_MISSING_MIN_MAC_LENGTH = -58,
    KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH = -59,
    KM_ERROR_CANNOT_ATTEST_IDS = -66,
    KM_ERROR_DEVICE_LOCKED = -72,
    KM_ERROR_UNIMPLEMENTED = -100,
    KM_ERROR_VERSION_MISMATCH = -101,
    KM_ERROR_UNKNOWN_ERROR = -1000
} KM_ERROR;

typedef enum SWD_COMMAND_HANDLER {
    SWD_COMMAND_HANDLER_swd_add_rng_entropy = 1,
    SWD_COMMAND_HANDLER_swd_export_key = 5,
    SWD_COMMAND_HANDLER_swd_import_key = 4,
    SWD_COMMAND_HANDLER_swd_get_key_characteristics = 3,
    SWD_COMMAND_HANDLER_swd_begin = 8,
    SWD_COMMAND_HANDLER_swd_update = 9,
    SWD_COMMAND_HANDLER_swd_finish = 10,
    SWD_COMMAND_HANDLER_swd_abort = 0xb,
    SWD_COMMAND_HANDLER_swd_generate_key = 2,
    SWD_COMMAND_HANDLER_swd_encrypt_key = 0xd,
    SWD_COMMAND_HANDLER_swd_key_attest = 0xe,
    SWD_COMMAND_HANDLER_swd_configure = 0xf,
    SWD_COMMAND_HANDLER_swd_key_upgrade = 0x10,
    SWD_COMMAND_HANDLER_swd_generate_sak = 0x11,
    SWD_COMMAND_HANDLER_swd_install_gak = 0x12,
    SWD_COMMAND_HANDLER_swd_import_wrapped_key = 0x19,
    SWD_COMMAND_HANDLER_swd_compute_shared_hmac = 0x1b,
    SWD_COMMAND_HANDLER_swd_get_hmac_sharing_parameter = 0x1a,
    SWD_COMMAND_HANDLER_swd_verify_authorization = 0x1c,
    SWD_COMMAND_HANDLER_swd_generate_csr = 0x17,
    SWD_COMMAND_HANDLER_swd_install_sgak = 0x1e
} SWD_COMMAND_HANDLER;

typedef struct operation_handler_t {
    KM_ALGORITHM algorithm;
    void * begin;
    void * update;
    void * finish;
} operation_handler_t;

typedef struct tee_param_memref_t {
    void * buffer;
    int size;
} tee_param_memref_t;

typedef struct vector_t {
    uint8_t *data;
    size_t len;
} vector_t;

typedef union {
    uint32_t enumerated;    /* KM_ENUM and KM_ENUM_REP */
    bool boolean;           /* KM_BOOL */
    uint32_t integer;       /* KM_INT and KM_INT_REP */
    uint64_t long_integer;  /* KM_LONG */
    uint64_t date_time;     /* KM_DATE */
    vector_t blob;          /* KM_BIGNUM and KM_BYTES*/
} param_tag_t;

typedef struct keymaster_key_param_t {
    keymaster_tag_t tag;
    union {
        uint32_t enumerated;    /* KM_ENUM and KM_ENUM_REP */
        bool boolean;           /* KM_BOOL */
        uint32_t integer;       /* KM_INT and KM_INT_REP */
        uint64_t long_integer;  /* KM_LONG */
        uint64_t date_time;     /* KM_DATE */
        vector_t blob;          /* KM_BIGNUM and KM_BYTES*/
    };
} keymaster_key_param_t;

typedef struct keymaster_key_param_set_t {
    keymaster_key_param_t *params;
    size_t len;
} keymaster_key_param_set_t;

typedef struct keymaster_key_characteristics_t {
    keymaster_key_param_set_t hw_enforced;
    keymaster_key_param_set_t sw_enforced;
} keymaster_key_characteristics_t;

keymaster_tag_type_t keymaster_tag_get_type(keymaster_tag_t tag);
uint32_t keymaster_tag_mask_type(keymaster_tag_t tag);
keymaster_key_param_t keymaster_param_enum(keymaster_tag_t tag, uint32_t value);
keymaster_key_param_t keymaster_param_int(keymaster_tag_t tag, uint32_t value);
keymaster_key_param_t keymaster_param_long(keymaster_tag_t tag, uint64_t value);
keymaster_key_param_t keymaster_param_blob(keymaster_tag_t tag, vector_t *blob);
keymaster_key_param_t keymaster_param_bool(keymaster_tag_t tag);
keymaster_key_param_t keymaster_param_date(keymaster_tag_t tag, uint64_t value);
void init_param_set(keymaster_key_param_set_t *param_set, keymaster_key_param_t *key_params, size_t len);

void keymaster_free_params(keymaster_key_param_t* params, size_t len);
void keymaster_free_param_set(keymaster_key_param_set_t* param_set);
void keymaster_free_characteristics(keymaster_key_characteristics_t *characteristics);

const char *km_result_to_string(KM_Result ret);
const char *km_error_to_string(int error);
const char *km_key_format_to_string(int key_format);
const char *km_algorithm_to_string(int algorithm);
int km_algorithm_to_int(const char *str);
int km_purpose_to_int(const char *str);
int km_padding_to_int(const char *str);
int km_digest_to_int(const char *str);

#endif // _SKEYMASTER_DEFS_H_
