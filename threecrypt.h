#ifndef THREECRYPT_H
#define THREECRYPT_H

#define __STDC_FORMAT_MACROS
#include "macros.h"
#include <inttypes.h>
#include <stdlib.h>
#include <Base/macros.h>
#include <Skc/common.h>
#include "dragonfly_v1.h" /* Enable Dragonfly V1. */
#if defined(BASE_OS_UNIXLIKE) || defined(BASE_OS_WINDOWS)
#  if defined(BASE_OS_UNIXLIKE)
#    ifdef __NetBSD__
#      include <ncurses/ncurses.h>
#    else
#      include <ncurses.h>
#    endif
#  elif defined(BASE_OS_WINDOWS)
#    include <Base/errors.h>
#    include <windows.h>
#    include <conio.h>
#  else
#    error "Critical error. Not unixlike or windows, as already detected."
#  endif
#else
#  error "Unsupported OS."
#endif

#ifdef THREECRYPT_EXTERN_TERM_BUFFER_SIZE
#  define THREECRYPT_TERM_BUFFER_SIZE	THREECRYPT_EXTERN_TERM_BUFFER_SIZE
#else
#  define THREECRYPT_TERM_BUFFER_SIZE	120
#endif

enum {
  THREECRYPT_MODE_NONE,
  THREECRYPT_MODE_SYMMETRIC_ENC,
  THREECRYPT_MODE_SYMMETRIC_DEC,
  THREECRYPT_MODE_DUMP,
  THREECRYPT_NUM_MODE_ENUMS
};
#define THREECRYPT_NUM_MODES (THREECRYPT_NUM_MODE_ENUMS - 1)

enum {
  THREECRYPT_METHOD_NONE,
#ifdef THREECRYPT_DRAGONFLY_V1_H
  THREECRYPT_METHOD_DRAGONFLY_V1,
#else
#  error "Only supported method!"
#endif
  THREECRYPT_NUM_METHOD_ENUMS
};
#define THREECRYPT_NUM_METHODS (THREECRYPT_NUM_METHOD_ENUMS - 1)

#define THREECRYPT_ARGMAP_MAX_COUNT	100
#define THREECRYPT_MIN_ID_STR_BYTES	sizeof(SKC_DRAGONFLY_V1_ID)
#define THREECRYPT_MAX_ID_STR_BYTES	THREECRYPT_MIN_ID_STR_BYTES

typedef struct {
	Skc_Catena512_Input input;
	Base_MMap           input_map;
	Base_MMap           output_map;
	char*               input_filename;
	size_t              input_filename_size;
	char*               output_filename;
	size_t              output_filename_size;
	int                 mode;
} Threecrypt;

#define THREECRYPT_NULL_LITERAL (Threecrypt){0}

#define R_(p) p BASE_RESTRICT
BASE_BEGIN_DECLS
void print_help (void);
void threecrypt (int, R_(char**));
BASE_END_DECLS
#undef R_

#endif /* ! */
