#ifndef THREECRYPT_TERM_H
#define THREECRYPT_TERM_H
#include <shim/macros.h>
#include <shim/operations.h>

#define THREECRYPT_TERM_BUFFER_SIZE	120
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
#endif

SHIM_BEGIN_DECLS

static inline void
threecrypt_term_init ();
static inline void
threecrypt_term_end ();
int
threecrypt_term_get_sensitive_string (uint8_t *    SHIM_RESTRICT,
			              char const * SHIM_RESTRICT);
int
threecrypt_term_obtain_password (uint8_t *    SHIM_RESTRICT,
		                 char const * SHIM_RESTRICT,
		                 int const,
		                 int const);
int
threecrypt_term_obtain_password_checked (uint8_t *    SHIM_RESTRICT,
			                 uint8_t *    SHIM_RESTRICT,
			                 char const * SHIM_RESTRICT,
			                 char const * SHIM_RESTRICT,
			                 int const,
			                 int const);
void
threecrypt_term_notify (char const *);

SHIM_END_DECLS

void
threecrypt_term_init ()
{
#if    defined (SHIM_OS_UNIXLIKE)
	initscr();
	clear();
#elif  defined (SHIM_OS_WINDOWS)
	system( "cls" );
#else
#	error "Unsupported OS."
#endif
}
void
threecrypt_term_end ()
{
#if    defined (SHIM_OS_UNIXLIKE)
	endwin();
#elif  defined (SHIM_OS_WINDOWS)
	system( "cls" );
#else
#	error "Unsupported OS."
#endif
}

#endif /* ~ THREECRYPT_TERM_H */
