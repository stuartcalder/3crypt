#ifndef THREECRYPT_H
#define THREECRYPT_H
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdlib.h>
#include <symm/common.h>
#include <shim/macros.h>
#ifdef THREECRYPT_EXT_ENABLE_DRAGONFLY_V1
#	include <symm/dragonfly_v1.h>
#	include "dragonfly_v1.h"
#else
#	error "THREECRYPT_ENABLE_DRAGONFLY_V1 not defined... Currently the only supported crypto method."
#endif
#if    defined (SHIM_OS_UNIXLIKE) || defined (SHIM_OS_WINDOWS)
#	if    defined (SHIM_OS_UNIXLIKE)
#		ifdef __NetBSD__
#			include <ncurses/ncurses.h>
#		else
#			include <ncurses.h>
#		endif
#	elif  defined (SHIM_OS_WINDOWS)
#		include <shim/errors.h>
#		include <windows.h>
#		include <conio.h>
#	else
#		error "Critical error. Not unixlike or windows, as already detected."
#	endif
#else
#	error "Unsupported OS."
#endif /* ~ if defined (SHIM_OS_UNIXLIKE) || defined (SHIM_OS_WINDOWS) */
#ifdef THREECRYPT_EXT_TERM_BUFFER_SIZE
#	define THREECRYPT_TERM_BUFFER_SIZE	THREECRYPT_EXT_TERM_BUFFER_SIZE
#else
#	define THREECRYPT_TERM_BUFFER_SIZE	120
#endif
enum {
	THREECRYPT_MODE_NONE,
	THREECRYPT_MODE_SYMMETRIC_ENC,
	THREECRYPT_MODE_SYMMETRIC_DEC,
	THREECRYPT_MODE_DUMP,
	THREECRYPT_NUM_MODES
};
enum {
	THREECRYPT_METHOD_NONE,
#ifdef THREECRYPT_DRAGONFLY_V1_H
	THREECRYPT_METHOD_DRAGONFLY_V1,
#endif
	THREECRYPT_NUM_METHODS
};
#define THREECRYPT_ARGMAP_MAX_COUNT	100
#define THREECRYPT_MIN_ID_STRING_BYTES	sizeof(SYMM_DRAGONFLY_V1_ID)
#define THREECRYPT_MAX_ID_STRING_BYTES	sizeof(SYMM_DRAGONFLY_V1_ID)
#define THREECRYPT_NUMBER_METHODS	1

typedef struct Threecrypt_ {
	Symm_Catena_Input catena_input;
	Shim_Map          input_map;
	Shim_Map          output_map;
	char *            input_filename;
	char *            output_filename;
	size_t            input_filename_size;
	size_t            output_filename_size;
	int               mode;
} Threecrypt;
#define THREECRYPT_NULL_INIT { \
	.catena_input = SYMM_CATENA_INPUT_NULL_INIT, \
	.input_map = SHIM_MAP_NULL_INIT, \
	.output_map = SHIM_MAP_NULL_INIT, \
	.input_filename = NULL, \
	.output_filename = NULL, \
	.input_filename_size = 0, \
	.output_filename_size = 0, \
	.mode = 0 \
}

SHIM_BEGIN_DECLS

void
print_help ();
void
threecrypt (int, char **);

SHIM_END_DECLS

#endif /* ~ THREECRYPT_H */
