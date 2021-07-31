#ifndef THREECRYPT_ARGS_H
#define THREECRYPT_ARGS_H

#include <Base/args.h>
#include "threecrypt.h"

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_DECLS

Base_Arg_Handler_f* short_parser  (const char*);
Base_Arg_Handler_f* long_parser   (const char*);
Base_Arg_Parser_f*  arg_processor (const char*, R_(void*));

#define PROTOTYPE_HANDLER_(pfx) \
  void pfx##_handler (char**, const int, void* BASE_RESTRICT)
#define PROTOTYPE_EQUIVALENT_HANDLER_(fptr, hndl) \
  static Base_Arg_Handler_f* const fptr##_handler = hndl##_handler

PROTOTYPE_HANDLER_(h);
PROTOTYPE_EQUIVALENT_HANDLER_(help, h);
PROTOTYPE_HANDLER_(e);
PROTOTYPE_EQUIVALENT_HANDLER_(encrypt, e);
PROTOTYPE_HANDLER_(d);
PROTOTYPE_EQUIVALENT_HANDLER_(decrypt, d);
PROTOTYPE_HANDLER_(D);
PROTOTYPE_EQUIVALENT_HANDLER_(dump, D);
PROTOTYPE_HANDLER_(i);
PROTOTYPE_EQUIVALENT_HANDLER_(input, i);
PROTOTYPE_HANDLER_(o);
PROTOTYPE_EQUIVALENT_HANDLER_(output, o);
PROTOTYPE_HANDLER_(E);
PROTOTYPE_EQUIVALENT_HANDLER_(entropy, E);
#ifdef SKC_DRAGONFLY_V1_H
PROTOTYPE_HANDLER_(min_memory);
PROTOTYPE_HANDLER_(max_memory);
PROTOTYPE_HANDLER_(use_memory);
PROTOTYPE_HANDLER_(iterations);
PROTOTYPE_HANDLER_(pad_by);
PROTOTYPE_HANDLER_(pad_to);
PROTOTYPE_HANDLER_(pad_as_if);
PROTOTYPE_HANDLER_(use_phi);
#endif /* ! ifdef SKC_DRAGONFLY_V1_H */
#undef PROTOTYPE_EQUIVALENT_HANDLER_
#undef PROTOTYPE_HANDLER_

BASE_END_DECLS
#undef R_

#endif /* ! */
