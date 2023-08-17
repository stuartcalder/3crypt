#ifndef THREECRYPT_MACRO_H
#define THREECRYPT_MACRO_H

#include <SSC/Macro.h>
#include <SSC/Error.h>
#include <SSC/Typedef.h>

#ifdef THREECRYPT_EXTERN_DEBUG
 #define THREECRYPT_ASSERT(Bool)    SSC_assert(Bool)
 #define THREECRYPT_ASSERT_MSG(...) SSC_assertMsg(__VA_ARGS__)
#else
 #define THREECRYPT_ASSERT(Bool_)
 #define THREECRYPT_ASSERT_IS_NIL
 #define THREECRYPT_ASSERT_MSG(...)
 #define THREECRYPT_ASSERT_MSG_IS_NIL
#endif

#endif /* ! */
