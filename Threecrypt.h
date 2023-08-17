#ifndef THREECRYPT_H
#define THREECRYPT_H

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdlib.h>
#include "Macro.h"

#include <PPQ/Common.h>
#include "DragonflyV1.h" /* Enable Dragonfly V1. */

#if !defined(SSC_OS_UNIXLIKE) && !defined(SSC_OS_WINDOWS)
 #error "Unsupported OS."
#endif
#if   defined(SSC_OS_UNIXLIKE)
 #ifdef __has_include
  #if   __has_include(<ncurses.h>)
   #include <ncurses.h>
  #elif __has_include(<ncurses/ncurses.h>)
   #include <ncurses/ncurses.h>
  #else
   #error "Error: Couldn't find ncurses.h, which we require!"
  #endif
 #else /* We don't have __has_include. */
  #ifdef __NetBSD__
   #include <ncurses/ncurses.h>
  #else
   #include <ncurses.h>
  #endif
 #endif
#elif defined(SSC_OS_WINDOWS)
 #include <SSC/Error.h>
 #include <windows.h>
 #include <conio.h>
#endif

#ifdef THREECRYPT_EXTERN_TERM_BUFFER_SIZE
 #define THREECRYPT_TERM_BUFFER_SIZE	THREECRYPT_EXTERN_TERM_BUFFER_SIZE
#else
 #define THREECRYPT_TERM_BUFFER_SIZE	120
#endif

#define R_(p) p SSC_RESTRICT
SSC_BEGIN_C_DECLS

/* Describe 3crypt modes. */
typedef enum {
  THREECRYPT_MODE_NONE = 0,
  THREECRYPT_MODE_SYMMETRIC_ENC = 1,
  THREECRYPT_MODE_SYMMETRIC_DEC = 2,
  THREECRYPT_MODE_DUMP = 3,
  THREECRYPT_MODE_MCOUNT = 4,
} Threecrypt_Mode_t;
#define THREECRYPT_NUM_MODES 3

#ifdef THREECRYPT_EXTERN_MODE_DEFAULT
 #define THREECRYPT_MODE_DEFAULT THREECRYPT_EXTERN_MODE_DEFAULT
#else
 #define THREECRYPT_MODE_DEFAULT THREECRYPT_MODE_SYMMETRIC_ENC
#endif

/* Below, defining *_ISDEF to 1 implies that method is supported.
 * Defining *_ISDEF to 0 implies that method is unsupported. */

/* Describe 3crypt methods. */
#define THREECRYPT_METHOD_NONE 0
/* Do we support Dragonfly_V1? */
#ifdef THREECRYPT_DRAGONFLY_V1_H
 #define THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF 1
 #define THREECRYPT_METHOD_DRAGONFLY_V1 (THREECRYPT_METHOD_NONE + 1)
#else
 #define THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF 0 
#endif
#define THREECRYPT_NUM_METHODS   THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
#define THREECRYPT_METHOD_MCOUNT (THREECRYPT_NUM_METHODS + 1) /* Including NONE. */

/* Is there at least 1 method? */
#if (THREECRYPT_NUM_METHODS < 1)
 #error "No methods are supported!"
#endif

/* What is the default method? */
#ifndef THREECRYPT_METHOD_DEFAULT
 #if defined(THREECRYPT_EXTERN_METHOD_DEFAULT)
  #define THREECRYPT_METHOD_DEFAULT THREECRYPT_EXTERN_METHOD_DEFAULT
 #elif THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
  #define THREECRYPT_METHOD_DEFAULT THREECRYPT_METHOD_DRAGONFLY_V1
 #else
  #define THREECRYPT_METHOD_DEFAULT THREECRYPT_METHOD_NONE
 #endif
#endif

typedef int Threecrypt_Method_t;

#ifdef THREECRYPT_EXTERN_USE_ENTROPY
 #define THREECRYPT_USE_ENTROPY THREECRYPT_EXTERN_USE_ENTROPY
#else
  /* Dragonfly_V1 can use supplementary entropy from stdin. */
 #define THREECRYPT_USE_ENTROPY THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
#endif
#define THREECRYPT_USE_KEYFILES 0 /* Not implemented yet. */

#define THREECRYPT_ARGMAP_MAX_COUNT	100

#define THREECRYPT_MIN_ID_STR_BYTES INT_MAX /* Temporary... */
#define THREECRYPT_MAX_ID_STR_BYTES INT_MIN /* Temporary... */

#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
 #if (PPQ_DRAGONFLY_V1_ID_NBYTES < THREECRYPT_MIN_ID_STR_BYTES)
  #undef  THREECRYPT_MIN_ID_STR_BYTES
  #define THREECRYPT_MIN_ID_STR_BYTES PPQ_DRAGONFLY_V1_ID_NBYTES
 #endif
 #if (PPQ_DRAGONFLY_V1_ID_NBYTES > THREECRYPT_MAX_ID_STR_BYTES)
  #undef  THREECRYPT_MAX_ID_STR_BYTES
  #define THREECRYPT_MAX_ID_STR_BYTES PPQ_DRAGONFLY_V1_ID_NBYTES
 #endif
#endif

#if   THREECRYPT_MIN_ID_STR_BYTES == INT_MAX
 #error "THREECRYPT_MIN_ID_STR_BYTES never got set!"
#elif THREECRYPT_MAX_ID_STR_BYTES == INT_MIN
 #error "THREECRYPT_MAX_IS_STR_BYTES never got set!"
#endif

typedef struct {
  PPQ_Catena512Input  input;
  SSC_MemMap          input_map;
  SSC_MemMap          output_map;
  char*               input_filename;
  char*               output_filename;
  size_t              input_filename_size;
  size_t              output_filename_size;
  Threecrypt_Mode_t   mode;
  Threecrypt_Method_t method;
} Threecrypt;

#define THREECRYPT_NULL_LITERAL SSC_COMPOUND_LITERAL(\
                                 Threecrypt,\
                                 SSC_COMPOUND_LITERAL(PPQ_Catena512Input, 0),\
				 SSC_MEMMAP_NULL_LITERAL,\
				 SSC_MEMMAP_NULL_LITERAL,\
				 SSC_NULL, SSC_NULL, 0, 0,\
				 THREECRYPT_MODE_NONE,\
				 THREECRYPT_METHOD_NONE\
                                )
#define THREECRYPT_DEFAULT_LITERAL SSC_COMPOUND_LITERAL(\
                                    Threecrypt,\
				    SSC_COMPOUND_LITERAL(PPQ_Catena512Input, 0),\
				    SSC_MEMMAP_NULL_LITERAL,\
				    SSC_MEMMAP_NULL_LITERAL,\
				    SSC_NULL, SSC_NULL, 0, 0,\
				    THREECRYPT_MODE_DEFAULT,\
				    THREECRYPT_METHOD_DEFAULT\
                                   )
/* Default literal here passes uninitialized data like
 * THREECRYPT_NULL_LITERAL, except chooses the default method and mode. */

void print_help(const char* topic);
void threecrypt(int argc, R_(char**) argv);
SSC_END_C_DECLS
#undef R_

#endif /* ! */
