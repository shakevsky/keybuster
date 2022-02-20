/*
    Defines that can be modified here or set in Android.mk to compile variants
*/
#ifndef _CONFIG_H_
#define _CONFIG_H_

/*
    Define to use a new implementation of libkeymaster_helper.so
*/
// #define KEYMASTER_HELPER_SELF_IMPLEMENTATION

/*
    Define to use TEEGRIS TEEC API (libteecl.so)
*/
// #define TZOS_TEEGRIS

/*
    Define to use Kinibi API (lib)
*/
// #define TZOS_KINIBI

/*
    Define to use functions from libteecl.so
*/
// #define USE_LIBTEECL

#ifdef KEYMASTER_HELPER_SELF_IMPLEMENTATION

#if !defined(TZOS_TEEGRIS) && !defined(TZOS_KINIBI)
#error "Must specify TZOS (-DTZOS_TEEGRIS or -DTZOS_KINIBI)"
#endif // !defined(TZOS_TEEGRIS) && !defined(TZOS_KINIBI)

#if defined(TZOS_TEEGRIS) && defined(TZOS_KINIBI)
#error "Must choose only one TZOS"
#endif // defined(TZOS_TEEGRIS) && defined(TZOS_KINIBI)

#endif // KEYMASTER_HELPER_SELF_IMPLEMENTATION

#endif  // _CONFIG_H_
