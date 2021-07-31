#ifndef THREECRYPT_MACROS_H
#define THREECRYPT_MACROS_H

#include <Base/errors.h>
#include <Base/macros.h>

#ifdef THREECRYPT_EXTERN_DEBUG
#  define THREECRYPT_ASSERT(boolean) Base_assert(boolean)
#  define THREECRYPT_ASSERT_MSG(...) Base_assert_msg(__VA_ARGS__)
#else
#  define THREECRYPT_ASSERT(boolean)
#  define THREECRYPT_ASSERT_IS_NIL
#  define THREECRYPT_ASSERT_MSG(boolean, msg)
#  define THREECRYPT_ASSERT_MSG_IS_NIL
#endif

#endif /* ! */
