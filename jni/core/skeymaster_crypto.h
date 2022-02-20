#ifndef _SKEYMASTER_CRYPTO_H_
#define _SKEYMASTER_CRYPTO_H_

#include <stdlib.h>

typedef struct ASN1_VALUE_st ASN1_VALUE;

typedef struct ASN1_ITEM_st ASN1_ITEM_st, *PASN1_ITEM_st;

typedef struct ASN1_ITEM_st ASN1_ITEM;

typedef ASN1_ITEM ASN1_ITEM_EXP;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE_st, *PASN1_TEMPLATE_st;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;

struct ASN1_TEMPLATE_st {
    unsigned long flags;
    long tag;
    unsigned long offset;
    char * field_name;
    ASN1_ITEM_EXP * item;
};

struct ASN1_ITEM_st {
    char itype;
    long utype;
    ASN1_TEMPLATE * templates;
    long tcount;
    void * funcs;
    long size;
    char * sname;
};

struct ASN1_VALUE_st {
};

struct asn1_string_st {
    int length;
    int type;
    unsigned char * data;
    long flags;
};

typedef int ASN1_NULL;
typedef int ASN1_BOOLEAN;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_OCTET_STRING;

typedef int ASN1_aux_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg);

typedef struct ASN1_AUX_st {
    void *app_data;
    int flags;
    int ref_offset;     /* Offset of reference value */
    ASN1_aux_cb *asn1_cb;
    int enc_offset;     /* Offset of ASN1_ENCODING structure */
} ASN1_AUX;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;
typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct evp_pkey_st EVP_PKEY;


typedef struct stack_st _STACK;

struct stack_st {
    int num;
    char * * data;
    int sorted;
    int num_alloc;
    int (* comp)(void *, void *);
};

ASN1_VALUE * ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);

ASN1_INTEGER * ASN1_INTEGER_new(void);
void ASN1_INTEGER_free(ASN1_INTEGER *a);
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
ASN1_INTEGER * ASN1_INTEGER_dup(const ASN1_INTEGER *x);

ASN1_OCTET_STRING * ASN1_OCTET_STRING_new(void);
void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a);
int  ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a);

long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a);
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);

_STACK *sk_new_null(void);
size_t sk_push(_STACK *sk, void *p);
void *sk_delete(_STACK *sk, size_t where);
void sk_pop_free(_STACK *st, void(*func)(void *));
int sk_num(const _STACK *st);
void *sk_value(const _STACK *st, int i);

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);

#endif // _SKEYMASTER_CRYPTO_H_
