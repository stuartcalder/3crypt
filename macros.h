#ifndef THREECRYPT_MACROS_H
#define THREECRYPT_MACROS_H

#include <shim/errors.h>
#include <shim/macros.h>

#ifdef THREECRYPT_EXT_DEBUG
#	define THREECRYPT_HAS_ASSERT
#	define THREECRYPT_HAS_ASSERT_MESSAGE
#	define THREECRYPT_ASSERT(boolean) shim_assert(boolean)
#	define THREECRYPT_ASSERT_MSG(boolean, ...) shim_assert_msg(boolean, __VA_ARGS__)
#else
#	define THREECRYPT_ASSERT(boolean)          /* Nil */
#	define THREECRYPT_ASSERT_MSG(boolean, msg) /* Nil */
#endif
#endif /* ~ifndef THREECRYPT_MACROS_H */
