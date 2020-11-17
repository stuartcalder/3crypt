#include "threecrypt.h"
#include "args.h"
#include <shim/operations.h>
#include <shim/term.h>
#include <ctype.h>

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

static int
determine_crypto_method_ (Shim_Map * shim_map);
static void
threecrypt_encrypt_ (Threecrypt *);
static void
threecrypt_decrypt_ (Threecrypt *);
static void
threecrypt_dump_ (Threecrypt *);

SHIM_END_DECLS

void
threecrypt (int argc, char ** argv)
{
	Threecrypt tcrypt = THREECRYPT_NULL_INIT;
	shim_process_args( argc, argv, arg_processor, &tcrypt );
	if( tcrypt.mode == THREECRYPT_MODE_NONE )
		SHIM_ERRX ("Error: No mode specified.\n%s", Help_Suggestion);
	if( !tcrypt.input_filename )
		SHIM_ERRX ("Error: Input file not specified.\n%s", Help_Suggestion);
	SHIM_OPENBSD_UNVEIL (tcrypt.input_filename, "r");
	if( !shim_filepath_exists( tcrypt.input_filename ) )
		SHIM_ERRX ("Error: The input file %s does not seem to exist.\n%s", tcrypt.input_filename, Help_Suggestion);
	tcrypt.input_map.size = shim_enforce_get_filepath_size( tcrypt.input_filename );
	switch( tcrypt.mode ) {
		case THREECRYPT_MODE_SYMMETRIC_ENC: {
			if( !tcrypt.output_filename ) {
				size_t const buf_size = tcrypt.input_filename_size + sizeof(".3c");
				tcrypt.output_filename = (char *)shim_enforce_malloc( buf_size );
				tcrypt.output_filename_size = buf_size - 1;
				memcpy( tcrypt.output_filename,
					tcrypt.input_filename,
					tcrypt.input_filename_size );
				memcpy( tcrypt.output_filename + tcrypt.input_filename_size,
					".3c",
					sizeof(".3c") );
			}
			SHIM_OPENBSD_UNVEIL (tcrypt.output_filename, "rwc");
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			if( shim_filepath_exists( tcrypt.output_filename ) )
				SHIM_ERRX ("Error: The output file %s already seems to exist.\n", tcrypt.output_filename );
			threecrypt_encrypt_( &tcrypt );
		} break; /* THREECRYPT_MODE_SYMMETRIC_ENC */
		case THREECRYPT_MODE_SYMMETRIC_DEC: {
			if( !tcrypt.output_filename ) {
				if( tcrypt.input_filename_size < 4 )
					SHIM_ERRX ("Error: No output file specified.\n");
				tcrypt.output_filename_size = tcrypt.input_filename_size - 3;
				tcrypt.output_filename = (char *)shim_enforce_malloc( tcrypt.output_filename_size + 1 );
				if( strcmp( tcrypt.input_filename + tcrypt.output_filename_size, ".3c" ) == 0 ) {
					memcpy( tcrypt.output_filename,
						tcrypt.input_filename,
						tcrypt.output_filename_size );
					tcrypt.output_filename[ tcrypt.output_filename_size ] = '\0';
				} else {
					SHIM_ERRX ("Error: No output file specified.\n");
				}

			}
			SHIM_OPENBSD_UNVEIL (tcrypt.output_filename, "rwc");
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			if( shim_filepath_exists( tcrypt.output_filename ) )
				SHIM_ERRX ("Error: The output file %s already seems to exist.\n", tcrypt.output_filename );
			threecrypt_decrypt_( &tcrypt );
		} break; /* THREECRYPT_MODE_SYMMETRIC_DEC */
		case THREECRYPT_MODE_DUMP: {
			SHIM_OPENBSD_UNVEIL (NULL, NULL);
			SHIM_OPENBSD_PLEDGE ("stdio rpath tty", NULL);
			threecrypt_dump_( &tcrypt );
		} break; /* THREECRYPT_MODE_DUMP */
		default: {
			SHIM_ERRX ("Error: Invalid, unrecognized mode (%d)\n%s", tcrypt.mode, Help_Suggestion);
		} break;
	} /* switch( tcrypt.mode ) */
	free( tcrypt.input_filename );
	free( tcrypt.output_filename );
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
threecrypt_encrypt_ (Threecrypt * ctx) {
	switch( ctx->catena_input.padding_mode ) {
		case SYMM_COMMON_PAD_MODE_TARGET: {
			uint64_t target = ctx->catena_input.padding_bytes;
			if( target <  SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES )
				SHIM_ERRX ("Error: The --pad-to target (%" PRIu64 ") is too small!\n", target);
			if( (target - SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES < ctx->input_map.size ) )
				SHIM_ERRX ("Error: The input file size (%" PRIu64 ") is too large to --pad-to %" PRIu64 "\n",
					   ctx->input_map.size, target);
			target -= ctx->input_map.size;
			target -= SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
			ctx->catena_input.padding_bytes = target;
			ctx->catena_input.padding_mode = SYMM_COMMON_PAD_MODE_ADD;
		} break;
	}
	ctx->input_map.file = shim_enforce_open_filepath( ctx->input_filename, true );
	shim_enforce_map_memory( &ctx->input_map, true );
	ctx->output_map.file = shim_enforce_create_filepath( ctx->output_filename );
#ifdef THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC
	SHIM_STATIC_ASSERT (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC >  0, "Must be greater than 0");
	SHIM_STATIC_ASSERT (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC < 63, "Must be less than 63");
#	define DEFAULT_GARLIC_ UINT8_C (THREECRYPT_EXT_DRAGONFLY_V1_DEFAULT_GARLIC)
#else
#	define DEFAULT_GARLIC_ UINT8_C (23)
#endif
	if( !ctx->catena_input.g_low )
		ctx->catena_input.g_low = DEFAULT_GARLIC_;
	if( !ctx->catena_input.g_high )
		ctx->catena_input.g_high = DEFAULT_GARLIC_;
	if( ctx->catena_input.g_low > ctx->catena_input.g_high )
		ctx->catena_input.g_high = ctx->catena_input.g_low;
	if( !ctx->catena_input.lambda )
		ctx->catena_input.lambda = UINT8_C (1);
	Symm_Dragonfly_V1 dfly_v1;
	memcpy( &dfly_v1.secret.catena_input, &ctx->catena_input, sizeof(ctx->catena_input) );
	shim_secure_zero( &ctx->catena_input, sizeof(ctx->catena_input) );
	{ /* Get the password. */
		shim_term_init();
		memset( dfly_v1.secret.catena_input.password_buffer, 0,
			sizeof(dfly_v1.secret.catena_input.password_buffer) );
		memset( dfly_v1.secret.catena_input.check_buffer, 0,
			sizeof(dfly_v1.secret.catena_input.check_buffer) );
		int pw_size = shim_term_obtain_password_checked( dfly_v1.secret.catena_input.password_buffer,
								 dfly_v1.secret.catena_input.check_buffer,
								 SYMM_COMMON_PASSWORD_PROMPT,
								 SYMM_COMMON_REENTRY_PROMPT,
								 1,
								 SYMM_COMMON_MAX_PASSWORD_BYTES,
								 (SYMM_COMMON_MAX_PASSWORD_BYTES + 1) );
		dfly_v1.secret.catena_input.password_size = pw_size;
		shim_term_end();
	}
	{ /* Initialize the CSPRNG. */
		Symm_CSPRNG * csprng_p = &dfly_v1.secret.catena_input.csprng;
		symm_csprng_init( csprng_p );
		if( dfly_v1.secret.catena_input.supplement_entropy ) {
			shim_term_init();
			memset( dfly_v1.secret.catena_input.check_buffer, 0,
				sizeof(dfly_v1.secret.catena_input.check_buffer) );
			int pw_size = shim_term_obtain_password( dfly_v1.secret.catena_input.check_buffer,
								 SYMM_COMMON_ENTROPY_PROMPT,
								 1,
								 SYMM_COMMON_MAX_PASSWORD_BYTES,
								 (SYMM_COMMON_MAX_PASSWORD_BYTES + 1) );
			shim_term_end();
			symm_skein512_hash_native( &dfly_v1.secret.ubi512,
						   dfly_v1.secret.hash_out,
						   dfly_v1.secret.catena_input.check_buffer,
						   pw_size );
			shim_secure_zero( dfly_v1.secret.catena_input.check_buffer, sizeof(dfly_v1.secret.catena_input.check_buffer) );
			symm_csprng_reseed( csprng_p, dfly_v1.secret.hash_out );
			shim_secure_zero( dfly_v1.secret.hash_out, sizeof(dfly_v1.secret.hash_out) );
		}
	}
	/* Encrypt. */
	symm_dragonfly_v1_encrypt( &dfly_v1,
				   &ctx->input_map,
				   &ctx->output_map,
				   ctx->output_filename );
	shim_secure_zero( &dfly_v1, sizeof(dfly_v1) );
}
void
threecrypt_decrypt_ (Threecrypt * ctx) {
	ctx->input_map.file = shim_enforce_open_filepath( ctx->input_filename, true );
	shim_enforce_map_memory( &ctx->input_map, true );
	int const method = determine_crypto_method_( &ctx->input_map );
	switch( method ) {
#ifdef THREECRYPT_DRAGONFLY_V1_H
		case THREECRYPT_METHOD_DRAGONFLY_V1: {
			ctx->output_map.file = shim_enforce_create_filepath( ctx->output_filename );
			Symm_Dragonfly_V1_Decrypt dfly_dcrypt;
			memset( dfly_dcrypt.password, 0, sizeof(dfly_dcrypt.password) );
			{
				shim_term_init();
				dfly_dcrypt.password_size = shim_term_obtain_password( dfly_dcrypt.password,
										       SYMM_COMMON_PASSWORD_PROMPT,
										       1,
										       SYMM_COMMON_MAX_PASSWORD_BYTES,
										       (SYMM_COMMON_MAX_PASSWORD_BYTES + 1) );
				shim_term_end();
			}
			symm_dragonfly_v1_decrypt( &dfly_dcrypt,
						   &ctx->input_map,
						   &ctx->output_map,
						   ctx->output_filename );
			shim_secure_zero( &dfly_dcrypt, sizeof(dfly_dcrypt) );
		} break; /* THREECRYPT_METHOD_DRAGONFLY_V1 */
#endif
		case THREECRYPT_METHOD_NONE:
			SHIM_ERRX ("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
				   ctx->input_filename, Help_Suggestion);
			break;
		default:
			SHIM_ERRX ("Error: Invalid decryption method %d\n", method);
			break;
	} /* switch( method ) */
}
void
threecrypt_dump_ (Threecrypt * ctx) {
	ctx->input_map.file = shim_enforce_open_filepath( ctx->input_filename, true );
	shim_enforce_map_memory( &ctx->input_map, true );
	int method = determine_crypto_method_( &ctx->input_map );
	switch( method ) {
#ifdef THREECRYPT_DRAGONFLY_V1_H
		case THREECRYPT_METHOD_DRAGONFLY_V1:
			symm_dragonfly_v1_dump_header( &ctx->input_map, ctx->input_filename );
			break;
#endif
		case THREECRYPT_METHOD_NONE:
			SHIM_ERRX ("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
				   ctx->input_filename, Help_Suggestion);
			break;
		default:
			SHIM_ERRX ("Error: Invalid decryption method %d\n", method);
			break;
	} /* switch( method ) */
}
void
print_help () {
	puts( Help );
}
