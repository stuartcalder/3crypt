#ifndef THREECRYPT_COMMANDLINEARG_H
#define THREECRYPT_COMMANDLINEARG_H

#include <SSC/CommandLineArg.h>
#include "Threecrypt.h"

#define R_ SSC_RESTRICT
SSC_BEGIN_C_DECLS

int
decrypt_argproc(const int, char** R_, const int, void* R_);

int
dump_argproc(const int, char** R_, const int, void* R_);

int
encrypt_argproc(const int, char** R_, const int, void* R_);

int
entropy_argproc(const int, char** R_, const int, void* R_);

int
help_argproc(const int, char** R_, const int, void* R_);

int
input_argproc(const int, char** R_, const int, void* R_);

int
iterations_argproc(const int, char** R_, const int, void* R_);

#ifdef PPQ_DRAGONFLY_V1_H
int
max_memory_argproc(const int, char** R_, const int, void* R_);

int
min_memory_argproc(const int, char** R_, const int, void* R_);
#endif

int
output_argproc(const int, char** R_, const int, void* R_);

#ifdef PPQ_DRAGONFLY_V1_H
int
pad_as_if_argproc(const int, char** R_, const int, void* R_);

int
pad_by_argproc(const int, char** R_, const int, void* R_);

int
pad_to_argproc(const int, char** R_, const int, void* R_);

int
use_memory_argproc(const int, char** R_, const int, void* R_);

int
use_phi_argproc(const int, char** R_, const int, void* R_);
#endif

SSC_END_C_DECLS
#undef R_

#endif /* ! */
