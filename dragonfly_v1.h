#if !defined(THREECRYPT_DRAGONFLY_V1_H) && defined(THREECRYPT_EXTERN_ENABLE_DRAGONFLY_V1)
#define THREECRYPT_DRAGONFLY_V1_H

#include <Base/macros.h>
#include <Skc/dragonfly_v1.h>

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_DECLS
uint8_t  dfly_v1_parse_memory     (R_(const char*) mem_str , const int size);
uint8_t  dfly_v1_parse_iterations (R_(const char*) iter_str, const int size);
uint64_t dfly_v1_parse_padding    (R_(const char*) pad_str , const int size);
BASE_END_DECLS
#undef R_

#endif /* ! */
