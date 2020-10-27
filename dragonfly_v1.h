#if defined (SYMM_DRAGONFLY_V1_H) && !defined (THREECRYPT_DRAGONFLY_V1_H)
#define THREECRYPT_DRAGONFLY_V1_H
#include <stdint.h>
#include <shim/macros.h>

uint8_t
dfly_v1_parse_memory (char const * SHIM_RESTRICT mem_str,
		      int const                  size);

uint8_t
dfly_v1_parse_iterations (char const * SHIM_RESTRICT iter_str,
			  int const                  size);

uint64_t
dfly_v1_parse_padding (char const * SHIM_RESTRICT pad_str,
		       int const		  size);

#endif /* ~ THREECRYPT_DRAGONFLY_V1_H */
