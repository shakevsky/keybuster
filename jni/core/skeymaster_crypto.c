#include <skeymaster_libs.h>
#include <skeymaster_crypto.h>

ASN1_VALUE * ASN1_item_new(const ASN1_ITEM *it)
{
    return g_libcrypto->ASN1_item_new(it);
}

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it) {
    g_libcrypto->ASN1_item_free(val, it);
}

ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it)
{
    return g_libcrypto->ASN1_item_d2i(val, in, len, it);
}

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
{
    return g_libcrypto->ASN1_item_i2d(val, out, it);
}

ASN1_INTEGER * ASN1_INTEGER_new(void)
{
    return g_libcrypto->ASN1_INTEGER_new();
}

void ASN1_INTEGER_free(ASN1_INTEGER *a)
{
    g_libcrypto->ASN1_INTEGER_free(a);
}

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v)
{
    return g_libcrypto->ASN1_INTEGER_set(a, v);
}

ASN1_INTEGER * ASN1_INTEGER_dup(const ASN1_INTEGER *x)
{
    return g_libcrypto->ASN1_INTEGER_dup(x);
}

ASN1_OCTET_STRING * ASN1_OCTET_STRING_new(void)
{
    return g_libcrypto->ASN1_OCTET_STRING_new();
}

void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a)
{
    g_libcrypto->ASN1_OCTET_STRING_free(a);
}

int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len)
{
    return g_libcrypto->ASN1_OCTET_STRING_set(str, data, len);
}

ASN1_OCTET_STRING *ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a)
{
    return g_libcrypto->ASN1_OCTET_STRING_dup(a);
}

long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a)
{
    return g_libcrypto->ASN1_ENUMERATED_get(a);
}

int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v)
{
    return g_libcrypto->ASN1_ENUMERATED_set(a, v);
}

_STACK *sk_new_null(void)
{
    return g_libcrypto->sk_new_null();
}

size_t sk_push(_STACK *sk, void *p)
{
    return g_libcrypto->sk_push(sk, p);
}

void *sk_delete(_STACK *sk, size_t where) {
    return g_libcrypto->sk_delete(sk, where);
}

void sk_pop_free(_STACK *st, void(*func)(void *))
{
    g_libcrypto->sk_pop_free(st, func);
}

int sk_num(const _STACK *st)
{
    return g_libcrypto->sk_num(st);
}

void *sk_value(const _STACK *st, int i)
{
    return g_libcrypto->sk_value(st, i);
}

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
    return g_libcrypto->SHA256(d, n, md);
}
