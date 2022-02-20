#ifndef _SKEYMASTER_KEY_REQUEST_H_
#define _SKEYMASTER_KEY_REQUEST_H_

#include <stdlib.h>
#include <string.h>
#include <skeymaster_defs.h>

typedef struct key_request_t {
    vector_t application_id;
    vector_t application_data;
    int algorithm;
    int purpose;
    int padding;
    int digest;
    int enc_ver;
    int is_plain;
    int key_size;
    bool is_exportable;
    int mode;
    int public_exponent;
    int request;
    vector_t salt;
    vector_t iv;
    vector_t aad;
    vector_t auth_tag;
    vector_t hek_randomness;
    vector_t nonce;
} key_request_t;

void free_key_request(key_request_t *req);

#endif // _SKEYMASTER_KEY_REQUEST_H_
