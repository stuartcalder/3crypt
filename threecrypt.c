#include "threecrypt.h"
#include "term.h"
#include <shim/operations.h>
#include <ctype.h>

static char const * Mode_Already_Set = "Error: Programming mode already set\n(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";
static char const * Help_Suggestion =  "(Use 3crypt --help for more information)\n";
static char const * Help = "Usage: 3crypt <Mode> [Switches...]\n"
			   "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n\n"
			   "Modes\n"
			   "-----\n"
			   "-h, --help\t\tPrint this help output.\n"
			   "-e, --encrypt\t\tSymmetric encryption mode; encrypt a file using a passphrase.\n"
			   "-d, --decrypt\t\tSymmetric decryption mode; decrypt a file using a passphrase.\n"
			   "-D, --dump\t\tDump information on a 3crypt encrypt file; must specify an input file.\n\n"
			   "Switches\n"
			   "-----\n"
			   "-i, --input  <filename>\t\tSpecifies the input file.\n"
			   "-o, --output <filename>\t\tSpecifies the output file.\n"
			   "-E, --entropy\t\t\tProvide random input characters to increase the entropy of the pseudorandom number generator.\n\n"
#ifndef SYMM_DRAGONFLY_V1_H
#	error "Dragonfly V1 is the only supported method now."
#endif
			   "Dragonfly_V1 Encryption Options\n"
			   "-------------------------------\n"
			   "--min-memory  <number_bytes>[K|M|G]\tThe minimum amount of memory to consume during key-derivation. Minimum memory cost.\n"
			   "--max-memory  <number_bytes>[K|M|G]\tThe maximum amount of memory to consume during key-derivation. Maximum memory cost.\n"
			   "--use-memory <number_bytes>[K|M|G]\tThe precise amount of memory to consume during key-derivation. Precise memory cost.\n"
			   "    The more memory we use for key-derivation, the harder it will be to attack your password.\n"
			   "    Memory minimums and maximums are rounded down to the nearest power of 2.\n"
			   "--iterations <number>\tThe number of times to iterate the memory-hard function during key-derivation. Time cost.\n"
			   "--pad-by <number_bytes>[K|M|G]\tThe number of padding bytes to add to the encrypted file, to obfuscate its size.\n"
			   "--pad-to <number_bytes>[K|M|G]\tThe target number of bytes you want your encrypted file to be; Will fail if it's not big enough.\n"
			   "--use-phi\t\tWhether to enable the optional phi function.\n"
			   "    WARNING: The optional phi function hardens the key-derivation function against\n"
			   "    parallel adversaries, greatly increasing the work necessary to attack your\n"
			   "    password, but introduces the potential for cache-timing attacks...\n"
			   "    Do NOT use this feature unless you understand the security implications!\n";

SHIM_BEGIN_DECLS

void SHIM_PUBLIC
threecrypt (int const, char const *[]);
static uint8_t
dragonfly_parse_memory_ (char const * SHIM_RESTRICT,
			 char *       SHIM_RESTRICT,
			 int const);
static uint8_t
dragonfly_parse_iterations_ (char const * SHIM_RESTRICT,
			     char *       SHIM_RESTRICT,
			     int const);
static uint64_t
dragonfly_parse_padding_ (char const * SHIM_RESTRICT,
			  char *       SHIM_RESTRICT,
			  int const);
static void
process_io_args_ (Threecrypt *,
		  Threecrypt_Arg_Map *);
static void
process_mode_args_ (Threecrypt *,
		    Threecrypt_Arg_Map *);
static void
process_enc_args_ (Threecrypt *,
		   Threecrypt_Arg_Map *);
static int
shift_left_digits_ (char * SHIM_RESTRICT,
		    int);
static bool
argument_cmp_ (Threecrypt_Arg_Map *       arg_map,
	       int const                  index,
	       char const * SHIM_RESTRICT str,
	       size_t const               str_size);
static bool
next_string_is_valid_ (Threecrypt_Arg_Map * arg_map,
		       int const            index);

static inline void
arg_map_del_ (Threecrypt_Arg_Map * arg_map);
static inline void
set_mode_ (Threecrypt * tcrypt,
	   int          mode);
static inline bool
all_strings_are_consumed_ (Threecrypt_Arg_Map * arg_map);
static int
determine_crypto_method_ (Shim_Map * shim_map);
static void
threecrypt_arg_map_init_ (Threecrypt_Arg_Map *, int const, char const *[]);
static inline void
threecrypt_arg_map_del_ (Threecrypt_Arg_Map *);

SHIM_END_DECLS

void SHIM_PUBLIC
threecrypt (int const argc, char const *argv[])
{
	/* Initialize the Threecrypt data using zeroes.
	 * Process the I/O and mode command-line arguments.
	 */
	Threecrypt ctx;
	memset( &ctx, 0, sizeof(ctx) );
	Threecrypt_Arg_Map arg_map;
	threecrypt_arg_map_init_( &arg_map, argc, argv );
	char *temp = NULL; /* Initialize temp to NULL, so that if we don't end up using it
			      it will still be safe to free() it. */

	process_io_args_( &ctx, &arg_map );
	process_mode_args_( &ctx, &arg_map );
	/* Threecrypt branches depending upon the chosen mode. */
	switch( ctx.mode ) {
	default:
		{ /* Invalid mode integer. */
			threecrypt_arg_map_del_( &arg_map );
			SHIM_ERRX ("Error: Invalid, unrecognized mode (%d)\n%s",
				   ctx.mode,
				   Help_Suggestion);
		} break;
	case THREECRYPT_MODE_NONE:
		{ /* No mode was selected. */
			threecrypt_arg_map_del_( &arg_map );
			SHIM_ERRX ("Error: No mode selected.\n%s",
				   Help_Suggestion);
		} break;
	case THREECRYPT_MODE_SYMMETRIC_ENC:
		{ /* The user wants to symmetrically encrypt a file. */
			if( !ctx.input_filename ) {
				threecrypt_arg_map_del_( &arg_map );
				SHIM_ERRX ("Error: No input filename was specified.\n");
			}
			else if( !ctx.output_filename ) {
				/* When no output filename is specified, we simply append ".3c" to the
				 * input filename, and use that.
				 */
				size_t const output_filename_size = ctx.input_filename_size + sizeof(".3c");
				temp = (char *)malloc( output_filename_size );
				if( !temp )
					SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
				memcpy( temp                          , ctx.input_filename, ctx.input_filename_size );
				memcpy( temp + ctx.input_filename_size, ".3c"             , sizeof(".3c")           );
				ctx.output_filename = temp;
				ctx.output_filename_size = output_filename_size;
			}
			/* On OpenBSD we call unveil now, allow reading input file, reading/writing/creating the output file. */
			SHIM_OPENBSD_UNVEIL (ctx.input_filename, "r");
			SHIM_OPENBSD_UNVEIL (ctx.output_filename, "rwc");
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			/* Open the input file, and memory-map it readonly. */
			ctx.input_map.shim_file = shim_open_existing_filepath( ctx.input_filename, true );
			ctx.input_map.size = shim_file_size( ctx.input_map.shim_file );
			shim_map_memory( &ctx.input_map, true );
			/* Create an output file, then process the remaining symmetric encryption arguments. */
			ctx.output_map.shim_file = shim_create_filepath( ctx.output_filename );
			process_enc_args_( &ctx, &arg_map );
			if( !all_strings_are_consumed_( &arg_map ) ) {
				shim_close_file( ctx.output_map.shim_file );
				remove( ctx.output_filename );
				threecrypt_arg_map_del_( &arg_map );
				SHIM_ERRX ("Error: Unused, unnecessary command-line arguments.\n");
			}
#ifndef SYMM_DRAGONFLY_V1_H
#	error "This is the only supported method..."
#endif
			/* Set g_high and lambda, under certain conditions. */
			if( ctx.catena_input.g_low > ctx.catena_input.g_high )
				ctx.catena_input.g_high = ctx.catena_input.g_low;
			if( ctx.catena_input.lambda == UINT8_C (0) )
				ctx.catena_input.lambda = UINT8_C (1);
			Symm_Dragonfly_V1	dragonfly_v1;
			SHIM_STATIC_ASSERT (
				sizeof(dragonfly_v1.secret.catena_input) ==  sizeof(ctx.catena_input),
				"These are both Catena_Input structs, they should be the same size."
			);
			memcpy( &dragonfly_v1.secret.catena_input, &ctx.catena_input, sizeof(ctx.catena_input) );
			shim_secure_zero( &ctx.catena_input, sizeof(ctx.catena_input) );
			/* Get the password. */
			{
				threecrypt_term_init();
				memset( dragonfly_v1.secret.catena_input.password_buffer,
					0,
					sizeof(dragonfly_v1.secret.catena_input.password_buffer) );
				memset( dragonfly_v1.secret.catena_input.check_buffer,
					0,
					sizeof(dragonfly_v1.secret.catena_input.check_buffer) );
				int password_size = threecrypt_term_obtain_password_checked( dragonfly_v1.secret.catena_input.password_buffer,
											     dragonfly_v1.secret.catena_input.check_buffer,
											     SYMM_COMMON_PASSWORD_PROMPT,
											     SYMM_COMMON_REENTRY_PROMPT,
											     1,
											     SYMM_COMMON_MAX_PASSWORD_BYTES );
				dragonfly_v1.secret.catena_input.password_size = password_size;
				threecrypt_term_end();
			}
			/* Initialize the CSPRNG. */
			{
				Symm_CSPRNG *csprng_p = &dragonfly_v1.secret.catena_input.csprng;
				symm_csprng_init( csprng_p );
				if( dragonfly_v1.secret.catena_input.supplement_entropy ) {
					threecrypt_term_init();

					memset( dragonfly_v1.secret.catena_input.check_buffer,
						0,
						sizeof(dragonfly_v1.secret.catena_input.check_buffer) );
					int password_size = threecrypt_term_obtain_password( dragonfly_v1.secret.catena_input.check_buffer,
											     SYMM_COMMON_ENTROPY_PROMPT,
											     1,
											     SYMM_COMMON_MAX_ENTROPY_BYTES );
					threecrypt_term_end();
					symm_skein512_hash_native( &dragonfly_v1.secret.ubi512,
								   dragonfly_v1.secret.hash_out,
								   dragonfly_v1.secret.catena_input.check_buffer,
								   password_size );
					symm_csprng_reseed( csprng_p, dragonfly_v1.secret.hash_out );
					shim_secure_zero( dragonfly_v1.secret.hash_out, sizeof(dragonfly_v1.secret.hash_out) );

				}
			}
			symm_dragonfly_v1_encrypt( &dragonfly_v1,
						   &ctx.input_map,
						   &ctx.output_map,
						   ctx.output_filename );
		} break;
	case THREECRYPT_MODE_SYMMETRIC_DEC:
		{
			if( !all_strings_are_consumed_( &arg_map ) ) {
				threecrypt_arg_map_del_( &arg_map );
				SHIM_ERRX ("Error: Unused, unnecessary command-line arguments.\n");
			}
			else if( !ctx.input_filename ) {
				threecrypt_arg_map_del_( &arg_map );
				SHIM_ERRX ("Error: No input filename was specified.\n");
			}
			else if( (!ctx.output_filename) && (ctx.input_filename_size >= 4)
				&& (strcmp( ctx.input_filename + (ctx.input_filename_size - 3), ".3c" ) == 0) )
			{
				size_t const size = ctx.input_filename_size - 3;
				temp = (char *)malloc( size + 1 );
				if( !temp ) {
					threecrypt_arg_map_del_( &arg_map );
					SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
				}
				memcpy( temp, ctx.input_filename, size );
				temp[ size ] = '\0';
				ctx.output_filename = temp;
				ctx.output_filename_size = size;
			}
			SHIM_OPENBSD_UNVEIL (ctx.input_filename, "r");
			SHIM_OPENBSD_UNVEIL (ctx.output_filename, "rwc");
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			ctx.input_map.shim_file = shim_open_existing_filepath( ctx.input_filename, true );
			ctx.input_map.size = shim_file_size( ctx.input_map.shim_file );
			shim_map_memory( &ctx.input_map, true );
			int method = determine_crypto_method_( &ctx.input_map );
			switch( method ) {
			default:
				{
					shim_unmap_memory( &ctx.input_map );
					shim_close_file( ctx.input_map.shim_file );
					SHIM_ERRX ("Error: Invalid decryption method %d\n", method);
				} break;
			case THREECRYPT_METHOD_NONE:
				{
					shim_unmap_memory( &ctx.input_map );
					shim_close_file( ctx.input_map.shim_file );
					SHIM_ERRX ("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
						   ctx.input_filename, Help_Suggestion);
				} break;
#ifdef THREECRYPT_METHOD_DRAGONFLY_V1
			case THREECRYPT_METHOD_DRAGONFLY_V1:
				{
					ctx.output_map.shim_file = shim_create_filepath( ctx.output_filename );
					Symm_Dragonfly_V1_Decrypt dfly_dcrypt;
					memset( dfly_dcrypt.password, 0, sizeof(dfly_dcrypt.password) );
					{
						threecrypt_term_init();
						dfly_dcrypt.password_size = threecrypt_term_obtain_password( dfly_dcrypt.password,
													     SYMM_COMMON_PASSWORD_PROMPT,
													     1,
													     SYMM_COMMON_MAX_PASSWORD_BYTES );
						threecrypt_term_end();
					}
					symm_dragonfly_v1_decrypt( &dfly_dcrypt,
								   &ctx.input_map,
								   &ctx.output_map,
								   ctx.output_filename );
					shim_secure_zero( dfly_dcrypt.password, sizeof(dfly_dcrypt.password) );
				} break;
#endif /* ~ THREECRYPT_METHOD_DRAGONFLY_V1 */
			}
		} break;
	case THREECRYPT_MODE_DUMP:
		{
			if( !all_strings_are_consumed_( &arg_map ) )
				SHIM_ERRX ("Error: Unused, unnecessary command-line arguments.\n");
			/* OpenBSD. */
			SHIM_OPENBSD_UNVEIL (ctx.input_filename, "r");
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			SHIM_OPENBSD_PLEDGE ("stdio rpath tty", NULL);
			/* Setup the input map. */
			ctx.input_map.shim_file = shim_open_existing_filepath( ctx.input_filename, true );
			ctx.input_map.size = shim_file_size( ctx.input_map.shim_file );
			shim_map_memory( &ctx.input_map, true );
			int method = determine_crypto_method_( &ctx.input_map );
			switch( method ) {
			default:
				{ /* Undefined method integer. */
					shim_unmap_memory( &ctx.input_map );
					shim_close_file( ctx.input_map.shim_file );
					SHIM_ERRX ("Error: Invalid decryption method (%d)\n", method);
				} break;
			case THREECRYPT_METHOD_NONE:
				{ /* No method specified. */
					shim_unmap_memory( &ctx.input_map );
					shim_close_file( ctx.input_map.shim_file );
					SHIM_ERRX ("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
						   ctx.input_filename, Help_Suggestion);
				} break;
#ifdef THREECRYPT_METHOD_DRAGONFLY_V1
			case THREECRYPT_METHOD_DRAGONFLY_V1:
				{ /* Dumping Dragonfly_V1 header. */
					symm_dragonfly_v1_dump_header( &ctx.input_map,
								       ctx.input_filename );
				} break;
#endif /* ~ THREECRYPT_METHOD_DRAGONFLY_V1 */
			}
		} break;
	} /* ~ switch(ctx.mode) */
	free( temp );
} /* ~ threecrypt(...) */

#define KIBIBYTE_	1024
#define MEBIBYTE_	(KIBIBYTE_ * 1024)
#define GIBIBYTE_	(MEBIBYTE_ * 1024)

uint8_t
dragonfly_parse_memory_ (char const * SHIM_RESTRICT mem_string,
			 char *       SHIM_RESTRICT temp,
			 int const                  size)
{
	uintmax_t requested_bytes = 0;
	uint64_t multiplier = 1;
	int num_digits;
	memcpy( temp, mem_string, (size + 1) );
	for( int i = 0; i < size; ++i ) {
		switch( toupper( (unsigned char)mem_string[ i ] ) ) {
		case ('K'):
			multiplier = (KIBIBYTE_ / 64);
			goto Have_Mul_Label;
		case ('M'):
			multiplier = (MEBIBYTE_ / 64);
			goto Have_Mul_Label;
		case ('G'):
			multiplier = (GIBIBYTE_ / 64);
			goto Have_Mul_Label;
		default:
			if( !isdigit( (unsigned char)mem_string[ i ] ) )
				SHIM_ERRX ("Error: Invalid memory string.\n");
		}
	}
Have_Mul_Label:
	num_digits = shift_left_digits_( temp, size );
	if( num_digits == 0 )
		SHIM_ERRX ("Error: No number supplied with memory-usage specification!\n");
#define BYTE_MAX_		UINT64_C (1000)
#define KIBIBYTE_MAX_		UINT64_C (17592186044416)
#define MEBIBYTE_MAX_		UINT64_C (17179869184)
#define GIBIBYTE_MAX_		UINT64_C (16777216)
#define INVALID_MEM_PARAM_	"Error: Specified memory parameter is too large!\n"
	switch( multiplier ) {
	case 1:
		if( num_digits > BYTE_MAX_ )
			SHIM_ERRX (INVALID_MEM_PARAM_);
		break;
	case KIBIBYTE_:
		if( num_digits > KIBIBYTE_MAX_ )
			SHIM_ERRX (INVALID_MEM_PARAM_);
		break;
	case MEBIBYTE_:
		if( num_digits > MEBIBYTE_MAX_ )
			SHIM_ERRX (INVALID_MEM_PARAM_);
		break;
	case GIBIBYTE_:
		if( num_digits > GIBIBYTE_MAX_ )
			SHIM_ERRX (INVALID_MEM_PARAM_);
		break;
	}
	requested_bytes = strtoumax( temp, NULL, 10 );
	requested_bytes *= multiplier;
	if( requested_bytes == 0 )
		SHIM_ERRX ("Error: Zero memory requested?\n");
	uint64_t mask = UINT64_C (0x8000000000000000);
	uint8_t garlic = 63;
	while( !(mask & requested_bytes) ) {
		mask >>= 1;
		--garlic;
	}
	return garlic;
}
uint8_t
dragonfly_parse_iterations_ (char const * SHIM_RESTRICT iter_string,
			     char *       SHIM_RESTRICT temp,
			     int const                  size)
{
	memcpy( temp, iter_string, (size + 1) );
	int num_digits = shift_left_digits_( temp, size );
	if( num_digits > 3 || num_digits == 0 )
		SHIM_ERRX ("Error: Invalid iteration count.\n");
	int it = atoi( temp );
	if( it < 1 || it > 255 )
		SHIM_ERRX ("Error: Invalid iteration count.\n");
	return (uint8_t)it;
}
uint64_t
dragonfly_parse_padding_ (char const * SHIM_RESTRICT pad_string,
			  char *       SHIM_RESTRICT temp,
			  int const                  size)
{
	memcpy( temp, pad_string, (size + 1) );
	uint64_t multiplier = 1;
	int num_digits;
	for( int i = 0; i < size; ++i ) {
		switch( toupper( (unsigned char)pad_string[ i ] ) ) {
		case 'K':
			multiplier = KIBIBYTE_;
			goto Have_Mul_L;
		case 'M':
			multiplier = MEBIBYTE_;
			goto Have_Mul_L;
		case 'G':
			multiplier = GIBIBYTE_;
			goto Have_Mul_L;
		}
	}
Have_Mul_L:
	num_digits = shift_left_digits_( temp, size );
	if( num_digits == 0 )
		SHIM_ERRX ("Error: Asked for padding, without providing a random number of padding bytes.\n");
	uintmax_t pad;
	pad = strtoumax( temp, NULL, 10 );
	return ((uint64_t)pad) * multiplier;
}
void
process_io_args_ (Threecrypt *         tcrypt_ctx,
		  Threecrypt_Arg_Map * arg_map)
{
	if( !arg_map->strings )
		return;
	int const count = arg_map->count;
#define ERROR_TOO_SMALL_	"Error: String %s is too small!\n"
	for( int i = 0; i < count; ++i ) {
		if( arg_map->strings[ i ] ) {
			if( argument_cmp_( arg_map, i, "-i"     , sizeof("-i")      ) ||
			    argument_cmp_( arg_map, i, "--input", sizeof("--input") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					if( arg_map->sizes[ i ] < 1 )
						SHIM_ERRX (ERROR_TOO_SMALL_, arg_map->strings[ i ]);
					tcrypt_ctx->input_filename = arg_map->strings[ ++i ];
					tcrypt_ctx->input_filename_size = arg_map->sizes[ i ];
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "-o"      , sizeof("-o")       ) ||
			    argument_cmp_( arg_map, i, "--output", sizeof("--output") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					if( arg_map->sizes[ i ] < 1 )
						SHIM_ERRX (ERROR_TOO_SMALL_, arg_map->strings[ i ]);
					tcrypt_ctx->output_filename = arg_map->strings[ ++i ];
					tcrypt_ctx->output_filename_size = arg_map->sizes[ i ];
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "-h"    , sizeof("-h")     ) ||
			    argument_cmp_( arg_map, i, "--help", sizeof("--help") ) ) {
				fputs( Help, stdout );
				exit( EXIT_SUCCESS );
			}
		} /* if( arg_map->strings[ i ] ) */
	} /* for( int i = 0; i < count; ++i ) */
}
void
process_mode_args_ (Threecrypt *         tcrypt_ctx,
		    Threecrypt_Arg_Map * arg_map)
{
	if( !arg_map->strings )
		return;
	int const count = arg_map->count;
	for( int i = 0; i < count; ++i ) {
		if( arg_map->strings[ i ] ) {
			if( argument_cmp_( arg_map, i, "-e"       , sizeof("-e")        ) ||
			    argument_cmp_( arg_map, i, "--encrypt", sizeof("--encrypt") ) ) {
				arg_map->strings[ i ] = NULL;
				set_mode_( tcrypt_ctx, THREECRYPT_MODE_SYMMETRIC_ENC );
			} else
			if( argument_cmp_( arg_map, i, "-d"       , sizeof("-d") ) ||
			    argument_cmp_( arg_map, i, "--decrypt", sizeof("--decrypt") ) ) {
				arg_map->strings[ i ] = NULL;
				set_mode_( tcrypt_ctx, THREECRYPT_MODE_SYMMETRIC_DEC );
			} else
			if( argument_cmp_( arg_map, i, "-D", sizeof("-D") ) ||
			    argument_cmp_( arg_map, i, "--dump", sizeof("--dump") ) ) {
				arg_map->strings[ i ] = NULL;
				set_mode_( tcrypt_ctx, THREECRYPT_MODE_DUMP );
			}
		}
	}
}
void
process_enc_args_ (Threecrypt *         tcrypt_ctx,
		   Threecrypt_Arg_Map * arg_map)
{
	int const count = arg_map->count;
	char * const temp = (char *)malloc( arg_map->max_string_size + 1 );
	if( !temp )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	tcrypt_ctx->catena_input.supplement_entropy = false;
#ifndef SYMM_DRAGONFLY_V1_H
#	error "Dragonfly V1 not here where we need it! No alternatives implemented."
#endif
#ifdef THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC
	SHIM_STATIC_ASSERT (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC >  0, "Must be greater than 0.");
	SHIM_STATIC_ASSERT (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC < 63, "Must be less than 63.");
#	define DEFAULT_GARLIC_ UINT8_C (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC)
#else
#	define DEFAULT_GARLIC_ UINT8_C (23)
#endif
	tcrypt_ctx->catena_input.padding_bytes = 0;
	tcrypt_ctx->catena_input.g_low  = DEFAULT_GARLIC_;
	tcrypt_ctx->catena_input.g_high = DEFAULT_GARLIC_;
	tcrypt_ctx->catena_input.lambda  = UINT8_C (1);
	tcrypt_ctx->catena_input.use_phi = UINT8_C (0);
	for( int i = 0; i < count; ++i ) {
		if( arg_map->strings[ i ] ) {
			if( argument_cmp_( arg_map, i, "-E"       , sizeof("-E")        ) ||
			    argument_cmp_( arg_map, i, "--entropy", sizeof("--entropy") ) ) {
				arg_map->strings[ i ] = NULL;
				tcrypt_ctx->catena_input.supplement_entropy = true;
			} else
#ifndef SYMM_DRAGONFLY_V1_H
#	error "Dragonfly V1 not here where we need it! No alternatives implemented."
#endif
			if( argument_cmp_( arg_map, i, "--min-memory", sizeof("--min-memory") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					tcrypt_ctx->catena_input.g_low = dragonfly_parse_memory_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "--max-memory", sizeof("--max-memory") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					tcrypt_ctx->catena_input.g_high = dragonfly_parse_memory_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "--use-memory", sizeof("--use-memory") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					tcrypt_ctx->catena_input.g_high = dragonfly_parse_memory_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					tcrypt_ctx->catena_input.g_low = tcrypt_ctx->catena_input.g_high;
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "--iterations", sizeof("--iterations") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					tcrypt_ctx->catena_input.lambda = dragonfly_parse_iterations_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					arg_map->strings[ i ] = NULL;
				}
				arg_map->strings[ i ] = NULL;
			} else
			if( argument_cmp_( arg_map, i, "--use-phi", sizeof("--use-phi") ) ) {
				arg_map->strings[ i ] = NULL;
				tcrypt_ctx->catena_input.use_phi = UINT8_C (0x01);
			} else
			if( argument_cmp_( arg_map, i, "--pad-by", sizeof("--pad-by") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					tcrypt_ctx->catena_input.padding_bytes = dragonfly_parse_padding_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					arg_map->strings[ i ] = NULL;
				}
			} else
			if( argument_cmp_( arg_map, i, "--pad-to", sizeof("--pad-to") ) ) {
				arg_map->strings[ i ] = NULL;
				if( next_string_is_valid_( arg_map, i ) ) {
					++i;
					uint64_t target = dragonfly_parse_padding_( arg_map->strings[ i ], temp, arg_map->sizes[ i ] );
					arg_map->strings[ i ] = NULL;
					if( target < SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES ) {
						shim_unmap_memory( &tcrypt_ctx->input_map );
						shim_close_file( tcrypt_ctx->input_map.shim_file );
						shim_close_file( tcrypt_ctx->output_map.shim_file );
						remove( tcrypt_ctx->output_filename );
						SHIM_ERRX ("Error: The --pad-to target (%" PRIu64 ") is way too small!\n", target);
					}
					if( target - SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES < tcrypt_ctx->input_map.size ) {
						shim_unmap_memory( &tcrypt_ctx->input_map );
						shim_close_file( tcrypt_ctx->input_map.shim_file );
						shim_close_file( tcrypt_ctx->output_map.shim_file );
						remove( tcrypt_ctx->output_filename );
						SHIM_ERRX ("Error: The input map size (%" PRIu64 ") is too large to --pad-to %" PRIu64 "\n",
							   tcrypt_ctx->input_map.size, target);
					} else {
						tcrypt_ctx->catena_input.padding_bytes = target;
						tcrypt_ctx->catena_input.padding_bytes -= tcrypt_ctx->input_map.size;
						tcrypt_ctx->catena_input.padding_bytes -= SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
					}
				}
			}
		}
	}
	free( temp );
}
int
shift_left_digits_ (char * SHIM_RESTRICT str,
		    int size)
{
	int index = 0;
	for( int i = 0; i < size; ++i )
		if( isdigit( str[ i ] ) )
			str[ index++ ] = str[ i ];
	if( (index + 1) < size )
		str[ index + 1 ] = (char)'\0';
	return index;
}

bool
argument_cmp_ (Threecrypt_Arg_Map *       arg_map,
	       int const                  index,
	       char const * SHIM_RESTRICT str,
	       size_t const               str_size)
{
	if( arg_map->sizes[ index ] != (str_size - 1) )
		return false;
	return strcmp( arg_map->strings[ index ], str ) == 0;
}
bool
next_string_is_valid_ (Threecrypt_Arg_Map * arg_map,
		       int const            index)
{
	return ((index + 1) < arg_map->count) && arg_map->strings[ index + 1 ];
}

void
arg_map_init_ (Threecrypt_Arg_Map *        arg_map,
	       int const                   argc,
	       char const ** SHIM_RESTRICT argv)
{
#define BAD_ARG_COUNT_ "Error: Invalid arg count\n"
	if( argc == 0 )
		SHIM_ERRX (BAD_ARG_COUNT_);
	if( argc > THREECRYPT_ARGMAP_MAX_COUNT )
		SHIM_ERRX (BAD_ARG_COUNT_);
	arg_map->count = argc - 1;
	if( arg_map->count == 0 ) {
		arg_map->strings = NULL;
		arg_map->sizes   = NULL;
		return;
	}
	char const ** args = argv + 1;
	arg_map->strings = (char const **)malloc( sizeof(char *) * arg_map->count );
	if( !arg_map->strings )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	arg_map->sizes = (size_t *)malloc( sizeof(size_t) * arg_map->count );
	if( !arg_map->sizes )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	arg_map->max_string_size = 0;
	memcpy( arg_map->strings, args, (sizeof(char *) * arg_map->count) );
	for( int i = 0; i < arg_map->count; ++i ) {
		arg_map->sizes[ i ] = strlen( arg_map->strings[ i ] );
		if( arg_map->sizes[ i ] > arg_map->max_string_size )
			arg_map->max_string_size = arg_map->sizes[ i ];
	}
}
void
arg_map_del_ (Threecrypt_Arg_Map * arg_map)
{
	free( arg_map->strings );
	free( arg_map->sizes   );
}
void
set_mode_ (Threecrypt * tcrypt,
	   int          mode)
{
	if( tcrypt->mode != THREECRYPT_MODE_NONE )
		SHIM_ERRX ("%s\n%s\n", Mode_Already_Set, Help_Suggestion);
	tcrypt->mode = mode;
}
bool
all_strings_are_consumed_ (Threecrypt_Arg_Map * arg_map)
{
	for( int i = 0; i < arg_map->count; ++i )
		if( arg_map->strings[ i ] )
			return false;
	return true;
}
int
determine_crypto_method_ (Shim_Map * shim_map)
{
	if( shim_map->size < THREECRYPT_MIN_ID_STRING_BYTES )
		return THREECRYPT_METHOD_NONE;
#ifdef SYMM_DRAGONFLY_V1_H
	{
		SHIM_STATIC_ASSERT (sizeof(SYMM_DRAGONFLY_V1_ID) >= THREECRYPT_MIN_ID_STRING_BYTES, "Less than the minimum # of ID bytes.");
		SHIM_STATIC_ASSERT (sizeof(SYMM_DRAGONFLY_V1_ID) <= THREECRYPT_MAX_ID_STRING_BYTES, "More than the maximum # of ID bytes.");
		if( memcmp( shim_map->ptr, SYMM_DRAGONFLY_V1_ID, sizeof(SYMM_DRAGONFLY_V1_ID) ) == 0 )
			return THREECRYPT_METHOD_DRAGONFLY_V1;
	}
#endif
	return THREECRYPT_METHOD_NONE;
}

void
threecrypt_arg_map_init_ (Threecrypt_Arg_Map *arg_map, int const argc, char const *argv[])
{
#define BAD_ARG_MAP_ARG_COUNT_ "Error: Invalid arg count in Threecrypt_Arg_Map\n"
	if( argc == 0 )
		SHIM_ERRX (BAD_ARG_MAP_ARG_COUNT_);
	if( argc > THREECRYPT_ARGMAP_MAX_COUNT )
		SHIM_ERRX (BAD_ARG_MAP_ARG_COUNT_);
	arg_map->count = argc - 1;
	if( arg_map->count == 0 ) {
		arg_map->strings = NULL;
		arg_map->sizes = NULL;
		arg_map->max_string_size = 0;
		return;
	}
	char const **args =  argv + 1;
	size_t const num_bytes = sizeof(char *) * arg_map->count;
	arg_map->strings = (char const **)malloc( num_bytes );
	if( !arg_map->strings )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	arg_map->sizes = (size_t *)malloc( sizeof(size_t) * arg_map->count );
	if( !arg_map->sizes )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	arg_map->max_string_size = 0;
	memcpy( arg_map->strings, args, num_bytes );
	for( int i = 0; i < arg_map->count; ++i ) {
		arg_map->sizes[ i ] = strlen( arg_map->strings[ i ] );
		if( arg_map->sizes[ i ] > arg_map->max_string_size )
			arg_map->max_string_size = arg_map->sizes[ i ];
	}
}
void
threecrypt_arg_map_del_ (Threecrypt_Arg_Map *arg_map)
{
	free( arg_map->strings );
	free( arg_map->sizes   );
}









