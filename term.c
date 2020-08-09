#include "term.h"

#if    defined (SHIM_OS_UNIXLIKE)
#	define NEWLINE_ "\n"
#elif  defined (SHIM_OS_WINDOWS)
#	define NEWLINE_ "\n\r"
#else
#	error "Unsupported OS."
#endif

#define OS_PROMPT_ "> " NEWLINE_

int
threecrypt_term_get_sensitive_string (uint8_t *    SHIM_RESTRICT buffer,
			   	      char const * SHIM_RESTRICT prompt)
{
	SHIM_STATIC_ASSERT (THREECRYPT_TERM_BUFFER_SIZE >= 2, "Minimum buffer size of 2 bytes.");
#define MAX_PASSWORD_SIZE_	(THREECRYPT_TERM_BUFFER_SIZE - 1)
#if    defined (SHIM_OS_UNIXLIKE)
	cbreak();
	noecho();
	keypad( stdscr, TRUE );
	int index = 0;
	WINDOW *w = newwin( 5, MAX_PASSWORD_SIZE_ + 10, 0, 0 );
	keypad( w, TRUE );
	bool outer, inner;
	outer = true;
	while( outer ) {
		memset( buffer, 0, THREECRYPT_TERM_BUFFER_SIZE );
		wclear( w );
		wmove( w, 1, 0 );
		waddstr( w, prompt );
		inner = true;
		while( inner ) {
			int ch = wgetch( w );
			switch( ch ) {
			/* Delete */
			case (127):
			case (KEY_DC):
			case (KEY_LEFT):
			case (KEY_BACKSPACE):
				{
					if( index > 0 ) {
						int y, x;
						getyx( w, y, x );
						wdelch( w );
						wmove( w, y, x - 1 );
						wrefresh( w );
						buffer[ --index ] = UINT8_C (0x00);
					} /* if( index > 0 ) */
				} break;
			/* Return */
			case ('\n'):
			case (KEY_ENTER):
				{
					inner = false;
				} break;
			default:
				{
					if( index < MAX_PASSWORD_SIZE_ ) {
						waddch( w, '*' );
						wrefresh( w );
						buffer[ index++ ] = (uint8_t)ch;
					}
				} break;
			} /* switch( ch ) */
		} /* while( inner ) */
		outer = false;
	} /* while( outer ) */
	int const password_size = strlen( (char *)buffer );
	delwin( w );
	return password_size;
#elif  defined (SHIM_OS_WINDOWS)
	int index = 0;
	bool repeat_ui, repeat_input;
	repeat_ui = true;
	while( repeat_ui ) {
		memset( buffer, 0, THREECRYPT_TERM_BUFFER_SIZE );
		system( "cls" );
		if( _cputs( prompt ) != 0 )
			SHIM_ERRX ("Error: Failed to _cputs()\n");
		repeat_input = true;
		while( repeat_input ) {
			int ch = _getch();
			switch( ch ) {
				default:
					{
						if( (index < THREECRYPT_TERM_BUFFER_SIZE) && (ch >= 32) && (ch <= 126) ) {
							if( _putch( '*' ) == EOF )
								SHIM_ERRX ("Error: Failed to _putch()\n");
							buffer[ index++ ] = (uint8_t)ch;
						}
					} break;
				case ('\b'):
					{
						if( index > 0 ) {
							if( _cputs( "\b \b" ) != 0 )
								SHIM_ERRX ("Error: Failed to _cputs()\n");
							buffer[ --index ] = UINT8_C (0);
						}
					} break;
				case ('\r'):
					{
						repeat_input = false;
					} break;
			} /* switch( ch ) */
		} /* while( repeat_input ) */
		repeat_ui = false;
	} /* while( repeat_ui ) */
	int const password_size = strlen( (char *)buffer );
	system( "cls" );
	return password_size;
#else
#	error "Unsupported OS."
#endif
}
int
threecrypt_term_obtain_password (uint8_t *    SHIM_RESTRICT password_buffer,
		       		 char const * SHIM_RESTRICT entry_prompt,
		       		 int const                  min_pw_size,
		       		 int const                  max_pw_size)
{
	int size;
	while( 1 ) {
		size = threecrypt_term_get_sensitive_string( password_buffer, entry_prompt );
		if( size < min_pw_size )
			threecrypt_term_notify( "Password is not long enough." NEWLINE_ );
		else if( size > max_pw_size )
			threecrypt_term_notify( "Password is too long." NEWLINE_ );
		else
			break;
	}
	return size;
}
int
threecrypt_term_obtain_password_checked (uint8_t *    SHIM_RESTRICT password_buffer,
			      		 uint8_t *    SHIM_RESTRICT check_buffer,
			      		 char const * SHIM_RESTRICT entry_prompt,
			      		 char const * SHIM_RESTRICT reentry_prompt,
			      		 int const                  min_pw_size,
			      		 int const                  max_pw_size)
{
	int size;
	while( 1 ) {
		size = threecrypt_term_get_sensitive_string( password_buffer, entry_prompt );
		if( size < min_pw_size ) {
			threecrypt_term_notify( "Password is not long enough." NEWLINE_ );
			continue;
		} else if( size > max_pw_size ) {
			threecrypt_term_notify( "Password is too long." NEWLINE_ );
			continue;
		} else if( threecrypt_term_get_sensitive_string( check_buffer, reentry_prompt ) != size ) {
			threecrypt_term_notify( "Second password not the same size as the first." NEWLINE_ );
			continue;
		}
		if( shim_ctime_memcmp( password_buffer, check_buffer, THREECRYPT_TERM_BUFFER_SIZE ) == 0 )
			break;
		threecrypt_term_notify( "Passwords do not match." NEWLINE_ );
	}
	return size;
}
void
threecrypt_term_notify (char const *notice)
{
#if    defined (SHIM_OS_UNIXLIKE)
	WINDOW *w = newwin( 1, strlen( notice ) + 1, 0, 0 );
	wclear( w );
	wmove( w, 0, 0 );
	waddstr( w, notice );
	wrefresh( w );
	wgetch( w );
	delwin( w );
#elif  defined (SHIM_OS_WINDOWS)
	system( "cls" );
	if( _cputs( notice ) != 0 )
		SHIM_ERRX ("Error: Failed to _cputs()\n");
	system( "pause" );
	system( "cls" );
#else
#	error "Unsupported OS."
#endif
}



