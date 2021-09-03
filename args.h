#ifndef THREECRYPT_ARGS_H
#define THREECRYPT_ARGS_H

#include <Base/args.h>
#include "threecrypt.h"

#define ARG_PROC_(name) int name##_argproc(const int, char** BASE_RESTRICT, const int, void* BASE_RESTRICT)
BASE_BEGIN_DECLS
ARG_PROC_(decrypt);
ARG_PROC_(dump);
ARG_PROC_(encrypt);
ARG_PROC_(entropy);
ARG_PROC_(help);
ARG_PROC_(input);
ARG_PROC_(iterations);
#ifdef SKC_DRAGONFLY_V1_H
ARG_PROC_(max_memory);
ARG_PROC_(min_memory);
#endif
ARG_PROC_(output);
#ifdef SKC_DRAGONFLY_V1_H
ARG_PROC_(pad_as_if);
ARG_PROC_(pad_by);
ARG_PROC_(pad_to);
ARG_PROC_(use_memory);
ARG_PROC_(use_phi);
#endif
BASE_END_DECLS
#undef ARG_PROC_

#endif /* ! */
