#ifndef _SKEYMASTER_KEY_PARAMS_H
#define _SKEYMASTER_KEY_PARAMS_H

#include <skeymaster_defs.h>
#include <skeymaster_asn1.h>

int is_repeatable_tag(keymaster_tag_t tag);
int km_push_param(
    km_param_t *par,
    keymaster_tag_t tag_value,
    ASN1_INTEGER *integer,
    ASN1_OCTET_STRING *string,
    int flags);
int km_get_tag(km_param_t *par, keymaster_tag_t tag, int tag_count, param_tag_t *param_tag);
int km_is_tag_value_exist(km_param_t *par, keymaster_tag_t tag, param_tag_t *ref_tag);
int km_add_tag(km_param_t *par ,keymaster_tag_t tag, param_tag_t *param_tag, int flags);
int km_del_tag(km_param_t *par, keymaster_tag_t tag);

km_param_t *km_param_set_to_asn1(keymaster_key_param_set_t *param_set);
int km_param_set_from_asn1(km_param_t *par, keymaster_key_param_set_t *param_set);

int is_tag_in_key_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag);

int add_key_parameter_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag);
int add_int_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, int value);
int add_date_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, uint64_t value);
int add_bool_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag);
int add_blob_to_param_set(keymaster_key_param_set_t *param_set, keymaster_tag_t tag, vector_t *value);

char *get_tag_string(keymaster_tag_t tag);


#endif // _SKEYMASTER_KEY_PARAMS_H
