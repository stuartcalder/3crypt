#if !defined(THREECRYPT_DRAGONFLY_V1_H) && defined(THREECRYPT_EXTERN_ENABLE_DRAGONFLY_V1)
#define THREECRYPT_DRAGONFLY_V1_H

#include <Base/macros.h>
#include <Skc/dragonfly_v1.h>

#define R_ BASE_RESTRICT
BASE_BEGIN_C_DECLS

/* TODO: Documentation. */
uint8_t
dfly_v1_parse_memory(const char* R_ mem_str , const int size);

/* TODO: Documentation. */
uint8_t
dfly_v1_parse_iterations(const char* R_ iter_str, const int size);

/* TODO: Documentation. */
uint64_t
dfly_v1_parse_padding(const char* R_ pad_str , const int size);

BASE_END_C_DECLS
#undef R_

#endif
