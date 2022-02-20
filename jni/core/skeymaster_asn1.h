#ifndef _SKEYMASTER_ASN1_H_
#define _SKEYMASTER_ASN1_H_

#include <skeymaster_crypto.h>
#include <skeymaster_defs.h>

/** @brief Updates templates items from libcrypto
    @note Must be called before using skeymaster ASN1 functions (e.g. called in initalize_libs())
 */
void init_asn1_templates(void);

typedef struct km_symm_cipher_ctx_t {
    ASN1_OCTET_STRING *data;                                // offset: 0x00
    ASN1_OCTET_STRING *key;                                 // offset: 0x04
    int unk1;                                               // offset: 0x08
    int unk2;                                               // offset: 0x0c
    int max_key_len;                                        // offset: 0x10
    EVP_CIPHER_CTX *ctx;                                    // offset: 0x14
    EVP_CIPHER *cipher;                                     // offset: 0x18
    KM_ALGORITHM algorithm;                                 // offset: 0x1c
    KM_PURPOSE purpose;                                     // offset: 0x20
    KM_PADDING padding;                                     // offset: 0x24
    int digest;                                             // offset: 0x28
    int block_mode;                                         // offset: 0x2c
    int mac_length;                                         // offset: 0x30
    int min_mac_length;                                     // offset: 0x34
    int unk10;                                              // offset: 0x38
    ASN1_OCTET_STRING *last;                                // offset: 0x3c
} km_symm_cipher_ctx_t;

typedef struct km_cipher_ctx_t {
    KM_DIGEST digest;                                       // offset: 0x00
    KM_ALGORITHM algorithm;                                 // offset: 0x04
    KM_PURPOSE purpose;                                     // offset: 0x08
    KM_PADDING padding;                                     // offset: 0x0c
    char *d;                                                // offset: 0x10
    bool is_wrapped_sig;                                    // offset: 0x14
    EVP_MD_CTX *md_ctx;                                     // offset: 0x18
    EVP_PKEY_CTX *pkey_ctx;                                 // offset: 0x1c
    char buf_512[0x200];                                    // offset: 0x20
    int buf_len;                                            // offset: 0x220
    int pkey_size;                                          // offset: 0x224
    int key_size;                                           // offset: 0x228
    int is_decoded_pkey;                                    // offset: 0x22c
    OPENSSL_PADDING openssl_pad;                            // offset: 0x230
    char bla[0x10];                                         // offset: 0x234
    operation_handler_t *handler;                           // offset: 0x244
} km_cipher_ctx_t;

/****************************
* ASN1 items/templates/funcs
*****************************/

/*
ASN1_ITEM KM_PARAM = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_param_templates,
    .tcount = 0x3,
    .funcs = km_param_funcs,
    .size = 0x10,
    .sname = "KM_PARAM"
};
*/
typedef struct km_param_t {
    ASN1_INTEGER *tag;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *i;                                        // offset: 0x04, flags: 0x91, tag: 0x00
    ASN1_OCTET_STRING *b;                                   // offset: 0x08, flags: 0x91, tag: 0x01
    int flags;                                              // offset: 0x10
} km_param_t;
extern ASN1_ITEM KM_PARAM;
int swd_param_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg);

/*
ASN1_ITEM KM_KEY_BLOB = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_key_blob_templates,
    .tcount = 0x3,
    .funcs = km_key_blob_funcs,
    .size = 0xc,
    .sname = "KM_KEY_BLOB"
};
*/
typedef struct km_key_blob_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *key;                                 // offset: 0x04, flags: 0x00, tag: 0x00
    km_param_t *par;                                        // offset: 0x08, flags: 0x93, tag: 0x00
} km_key_blob_t;
extern ASN1_ITEM KM_KEY_BLOB;
int swd_key_blob_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg);
int should_mark_hidden_tag(keymaster_tag_t tag);
int km_mark_hidden_tags(km_param_t *par);
int km_del_tags_by_flag(km_param_t *par, int flag);

/*
ASN1_ITEM KM_EKEY_BLOB = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_ekey_blob_templates,
    .tcount = 0x3,
    .funcs = km_ekey_blob_funcs,
    .size = 0x10,
    .sname = "KM_EKEY_BLOB"
};
*/
typedef struct km_ekey_blob_t {
    km_key_blob_t *key_blob;
    ASN1_INTEGER *enc_ver;                                  // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *ekey;                                // offset: 0x08, flags: 0x00, tag: 0x00
    km_param_t *enc_par;                                    // offset: 0x0c, flags: 0x02, tag: 0x00
} km_ekey_blob_t;
extern ASN1_ITEM KM_EKEY_BLOB;
int swd_ekey_blob_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg);

/*
ASN1_ITEM KM_INDATA = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_indata_templates,
    .tcount = 0xc,
    .funcs = km_indata_funcs,
    .size = 0x34,
    .sname = "KM_INDATA"
};
*/
typedef struct km_indata_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *km_ver;                                   // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_INTEGER *cmd;                                      // offset: 0x08, flags: 0x00, tag: 0x00
    ASN1_INTEGER *pid;                                      // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_INTEGER *int0;                                     // offset: 0x10, flags: 0x91, tag: 0x00
    ASN1_INTEGER *long0;                                    // offset: 0x14, flags: 0x91, tag: 0x01
    ASN1_INTEGER *long1;                                    // offset: 0x18, flags: 0x91, tag: 0x02
    ASN1_OCTET_STRING *bin0;                                // offset: 0x1c, flags: 0x91, tag: 0x03
    ASN1_OCTET_STRING *bin1;                                // offset: 0x20, flags: 0x91, tag: 0x04
    ASN1_OCTET_STRING *bin2;                                // offset: 0x24, flags: 0x91, tag: 0x05
    ASN1_OCTET_STRING *key;                                 // offset: 0x28, flags: 0x91, tag: 0x06
    km_param_t *par;                                        // offset: 0x2c, flags: 0x93, tag: 0x08
    int flags;
} km_indata_t;

/*
ASN1_ITEM KM_OUTDATA = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_outdata_templates,
    .tcount = 0xa,
    .funcs = km_outdata_funcs,
    .size = 0x2c,
    .sname = "KM_OUTDATA"
};
*/
typedef struct km_outdata_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *cmd;                                      // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_INTEGER *pid;                                      // offset: 0x08, flags: 0x00, tag: 0x00
    ASN1_INTEGER *err;                                      // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_INTEGER *int0;                                     // offset: 0x10, flags: 0x91, tag: 0x00
    ASN1_INTEGER *long0;                                    // offset: 0x14, flags: 0x91, tag: 0x01
    ASN1_OCTET_STRING *bin0;                                // offset: 0x18, flags: 0x91, tag: 0x02
    ASN1_OCTET_STRING *bin1;                                // offset: 0x1c, flags: 0x91, tag: 0x03
    ASN1_OCTET_STRING *bin2;                                // offset: 0x20, flags: 0x91, tag: 0x04
    ASN1_OCTET_STRING *log;                                 // offset: 0x24, flags: 0x91, tag: 0x05
    int flags;
} km_outdata_t;

/*
ASN1_ITEM KM_OPERATION_ST = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_operation_st_templates,
    .tcount = 0x4,
    .funcs = km_operation_st_funcs,
    .size = 0x1c,
    .sname = "KM_OPERATION_ST"
*/
typedef struct km_operation_st_t {
    ASN1_OCTET_STRING *in;                                // offset: 0x00, flags: 0x01, tag: 0x00
    ASN1_OCTET_STRING *out;                               // offset: 0x04, flags: 0x01, tag: 0x00
    ASN1_OCTET_STRING *finish_out;                        // offset: 0x08, flags: 0x01, tag: 0x00
    ASN1_OCTET_STRING *signature;                         // offset: 0x0c, flags: 0x01, tag: 0x00
} km_operation_st_t;

/*
ASN1_ITEM KM_OPERATION = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_operation_templates,
    .tcount = 0x1,
    .funcs = km_operation_funcs,
    .size = 0x250,
    .sname = "KM_OPERATION"
};
*/
typedef struct km_operation_t {
    km_param_t *par;                                        // offset: 0x00, flags: 0x93, tag: 0x00
    km_cipher_ctx_t cipher_ctx;                             // offset: 0x04
} km_operation_t;

/*
ASN1_ITEM KM_KEY_OBJECT = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_key_object_templates,
    .tcount = 0x2,
    .funcs = NULL,
    .size = 0xc,
    .sname = "KM_KEY_OBJECT"
};
*/
typedef struct km_key_object_t {
    ASN1_OCTET_STRING *id;                                  // offset: 0x00, flags: 0x00, tag: 0x00
    km_param_t *par;                                        // offset: 0x04, flags: 0x93, tag: 0x00
} km_key_object_t;

/*
ASN1_ITEM KM_ROOT_OF_TRUST = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_root_of_trust_templates,
    .tcount = 0x4,
    .funcs = NULL,
    .size = 0x10,
    .sname = "KM_ROOT_OF_TRUST"
};
*/
typedef struct km_root_of_trust_t {
    ASN1_OCTET_STRING *verified_boot_key;                   // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_BOOLEAN *device_locked;                            // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_ENUMERATED *verified_boot_state;                   // offset: 0x08, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *verified_boot_hash;                  // offset: 0x0c, flags: 0x00, tag: 0x00
} km_root_of_trust_t;
extern ASN1_ITEM KM_ROOT_OF_TRUST;

/*
ASN1_ITEM KM_AUTH_LIST = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_auth_list_templates,
    .tcount = 0x25,
    .funcs = NULL,
    .size = 0x94,
    .sname = "KM_AUTH_LIST"
};
*/
typedef struct km_auth_list_t {
    ASN1_INTEGER *purpose;                                  // offset: 0x00, flags: 0x93, tag: 0x01
    ASN1_INTEGER *algorithm;                                // offset: 0x04, flags: 0x91, tag: 0x02
    ASN1_INTEGER *key_size;                                 // offset: 0x08, flags: 0x91, tag: 0x03
    ASN1_INTEGER *block_mode;                               // offset: 0x0c, flags: 0x93, tag: 0x04
    ASN1_INTEGER *digest;                                   // offset: 0x10, flags: 0x93, tag: 0x05
    ASN1_INTEGER *padding;                                  // offset: 0x14, flags: 0x93, tag: 0x06
    ASN1_NULL *caller_nonce;                                // offset: 0x18, flags: 0x91, tag: 0x07
    ASN1_INTEGER *min_mac_length;                           // offset: 0x1c, flags: 0x91, tag: 0x08
    ASN1_INTEGER *ec_curve;                                 // offset: 0x20, flags: 0x91, tag: 0x0a
    ASN1_INTEGER *rsa_public_exponent;                      // offset: 0x24, flags: 0x91, tag: 0xc8
    ASN1_NULL *rollback_resistance;                         // offset: 0x28, flags: 0x91, tag: 0x12f
    ASN1_INTEGER *active_date_time;                         // offset: 0x2c, flags: 0x91, tag: 0x190
    ASN1_INTEGER *origination_expire_date;                  // offset: 0x30, flags: 0x91, tag: 0x191
    ASN1_INTEGER *usage_expire_date;                        // offset: 0x34, flags: 0x91, tag: 0x192
    ASN1_NULL *no_auth_required;                            // offset: 0x38, flags: 0x91, tag: 0x1f7
    ASN1_INTEGER *user_auth_type;                           // offset: 0x3c, flags: 0x91, tag: 0x1f8
    ASN1_INTEGER *auth_timeout;                             // offset: 0x40, flags: 0x91, tag: 0x1f9
    ASN1_NULL *allow_while_on_body;                         // offset: 0x44, flags: 0x91, tag: 0x1fa
    ASN1_NULL *trusted_user_presence_req;                   // offset: 0x48, flags: 0x91, tag: 0x1fb
    ASN1_NULL *trusted_confirmation_req;                    // offset: 0x4c, flags: 0x91, tag: 0x1fc
    ASN1_NULL *unlocked_device_required;                    // offset: 0x50, flags: 0x91, tag: 0x1fd
    ASN1_INTEGER *creation_date_time;                       // offset: 0x54, flags: 0x91, tag: 0x2bd
    ASN1_INTEGER *origin;                                   // offset: 0x58, flags: 0x91, tag: 0x2be
    km_root_of_trust_t *root_of_trust;                      // offset: 0x5c, flags: 0x91, tag: 0x2c0
    ASN1_INTEGER *os_version;                               // offset: 0x60, flags: 0x91, tag: 0x2c1
    ASN1_INTEGER *os_patchlevel;                            // offset: 0x64, flags: 0x91, tag: 0x2c2
    ASN1_OCTET_STRING *attestation_application_id;          // offset: 0x68, flags: 0x91, tag: 0x2c5
    ASN1_OCTET_STRING *attestation_id_brand;                // offset: 0x6c, flags: 0x91, tag: 0x2c6
    ASN1_OCTET_STRING *attestation_id_device;               // offset: 0x70, flags: 0x91, tag: 0x2c7
    ASN1_OCTET_STRING *attestation_id_product;              // offset: 0x74, flags: 0x91, tag: 0x2c8
    ASN1_OCTET_STRING *attestation_id_serial;               // offset: 0x78, flags: 0x91, tag: 0x2c9
    ASN1_OCTET_STRING *attestation_id_imei;                 // offset: 0x7c, flags: 0x91, tag: 0x2ca
    ASN1_OCTET_STRING *attestation_id_meid;                 // offset: 0x80, flags: 0x91, tag: 0x2cb
    ASN1_OCTET_STRING *attestation_id_manufactuer;          // offset: 0x84, flags: 0x91, tag: 0x2cc
    ASN1_OCTET_STRING *attestation_id_model;                // offset: 0x88, flags: 0x91, tag: 0x2cd
    ASN1_INTEGER *vendor_patchlevel;                        // offset: 0x8c, flags: 0x91, tag: 0x2ce
    ASN1_INTEGER *boot_patchlevel;                          // offset: 0x90, flags: 0x91, tag: 0x2cf
} km_auth_list_t;

/*
ASN1_ITEM KM_WRAPPED_KEY_DESCRIPTION = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_wrapped_key_description_templates,
    .tcount = 0x2,
    .funcs = NULL,
    .size = 0x8,
    .sname = "KM_WRAPPED_KEY_DESCRIPTTION"
};*/
typedef struct km_wrapped_key_description_t {
    ASN1_INTEGER *key_format;                               // offset: 0x00, flags: 0x00, tag: 0x00
    km_auth_list_t *auth_list;                              // offset: 0x04, flags: 0x00, tag: 0x00
} km_wrapped_key_description_t;

/*
ASN1_ITEM KM_WRAPPED_KEY = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_wrapped_key_templates,
    .tcount = 0x6,
    .funcs = NULL,
    .size = 0x18,
    .sname = "KM_WRAPPED_KEY"
};
*/
typedef struct km_wrapped_key_t {
    ASN1_INTEGER *version;                                  // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *transit_key;                         // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *iv;                                  // offset: 0x08, flags: 0x00, tag: 0x00
    km_wrapped_key_description_t *wrapped_key_description;  // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *secure_key;                          // offset: 0x10, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *tag;                                 // offset: 0x14, flags: 0x00, tag: 0x00
} km_wrapped_key_t;

/*
ASN1_ITEM KM_VERIFICATION_TOKEN = {
    .itype = '\x01',
    .utype = 0x10,
    .templates = km_verification_token_templates,
    .tcount = 0x5,
    .funcs = NULL,
    .size = 0x14,
    .sname = "KM_VERIFICATION_TOKEN"
};
*/
typedef struct km_verification_token_t {
    ASN1_INTEGER *challenge;                                // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *timestamp;                                // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_INTEGER *security_level;                           // offset: 0x08, flags: 0x00, tag: 0x00
    km_param_t *paramaters_verified;                        // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *hmac;                                // offset: 0x10, flags: 0x00, tag: 0x00
} km_verification_token_t;

/****************************
* ASN1 related functions
*****************************/

int km_get_ASN1_INTEGER(ASN1_INTEGER *integer, int32_t *out);
ASN1_INTEGER *km_set_ASN1_INTEGER(long v);

int km_get_ASN1_INTEGER_BN(ASN1_INTEGER *integer, int64_t *out);
ASN1_INTEGER *km_set_ASN1_INTEGER_BN(uint64_t v);

int km_get_ASN1_OCTET_STRING(ASN1_OCTET_STRING *string, uint8_t **p_out, size_t *p_len);
ASN1_OCTET_STRING *km_set_ASN1_OCTET_STRING(uint8_t *data, size_t len);

void free_km_param(void *par);

km_indata_t * KM_INDATA_new(void);
void KM_INDATA_free(km_indata_t *indata);
int i2d_KM_INDATA(km_indata_t *indata, uint8_t **out);
km_indata_t *d2i_KM_INDATA(ASN1_VALUE **val, uint8_t **in, long len);

km_outdata_t *d2i_KM_OUTDATA(ASN1_VALUE **val, uint8_t **in, long len);
void KM_OUTDATA_free(km_outdata_t *outdata);

ASN1_OCTET_STRING *encode_ekey_blob(km_ekey_blob_t *ekey_blob);

#endif // _SKEYMASTER_ASN1_H_
