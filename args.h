#ifndef THREECRYPT_ARGS_H
#define THREECRYPT_ARGS_H
#include "threecrypt.h"
#include <shim/args.h>

SHIM_BEGIN_DECLS

Shim_Arg_Handler_f *
short_parser (char const *);

Shim_Arg_Handler_f *
long_parser (char const *);

Shim_Arg_Parser_f *
arg_processor (char const *, void * SHIM_RESTRICT);

#define PROTOTYPE_HANDLER_(prefix) \
	void prefix##_handler (char **, int const, void * SHIM_RESTRICT)
#define PROTOTYPE_EQUIVALENT_HANDLER_(f_ptr_prefix, handler_prefix) \
	static Shim_Arg_Handler_f * const f_ptr_prefix##_handler = handler_prefix##_handler

PROTOTYPE_HANDLER_ (h);
PROTOTYPE_EQUIVALENT_HANDLER_(help, h);
PROTOTYPE_HANDLER_ (e);
PROTOTYPE_EQUIVALENT_HANDLER_(encrypt, e);
PROTOTYPE_HANDLER_ (d);
PROTOTYPE_EQUIVALENT_HANDLER_(decrypt, d);
PROTOTYPE_HANDLER_ (D);
PROTOTYPE_EQUIVALENT_HANDLER_(dump, D);
PROTOTYPE_HANDLER_ (i);
PROTOTYPE_EQUIVALENT_HANDLER_(input, i);
PROTOTYPE_HANDLER_ (o);
PROTOTYPE_EQUIVALENT_HANDLER_(output, o);
PROTOTYPE_HANDLER_ (E);
PROTOTYPE_EQUIVALENT_HANDLER_(entropy, E);
#ifdef SYMM_DRAGONFLY_V1_H
PROTOTYPE_HANDLER_ (min_memory);
PROTOTYPE_HANDLER_ (max_memory);
PROTOTYPE_HANDLER_ (use_memory);
PROTOTYPE_HANDLER_ (iterations);
PROTOTYPE_HANDLER_ (pad_by);
PROTOTYPE_HANDLER_ (pad_to);
PROTOTYPE_HANDLER_ (pad_as_if);
PROTOTYPE_HANDLER_ (use_phi);
#endif /* ~ ifdef SYMM_DRAGONFLY_V1_H */
#undef PROTOTYPE_EQUIVALENT_HANDLER_
#undef PROTOTYPE_HANDLER_

SHIM_END_DECLS

#endif /* ~ THREECRYPT_ARGS_H */
