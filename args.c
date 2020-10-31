#include "args.h"

#ifdef THREECRYPT_EXT_STRICT_ARG_PROCESSING
#	define HANDLE_INVALID_ARG_(arg) SHIM_ERRX ("Error: Invalid argument: %s\n", arg)
#else
#	define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

Shim_Arg_Handler_t *
short_parser (char const * str) {
	size_t const str_size = strlen( str );
	switch( str_size ) {
		case 2: {
			switch( str[ 1 ] ) {
				case 'h':
					return h_handler;
				case 'e':
					return e_handler;
				case 'd':
					return d_handler;
				case 'D':
					return D_handler;
				case 'i':
					return i_handler;
				case 'o':
					return o_handler;
				case 'E':
					return E_handler;
			}
		} break;
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

#ifdef SYMM_DRAGONFLY_V1_H
#	define DFLY1_(code) code
#else
#	define DFLY1_(code) /*nil*/
#endif

Shim_Arg_Handler_t *
long_parser (char const * str) {
	size_t const str_size = strlen( str );
	switch( str_size ) {
		case 6: {
			if( strcmp( str, "--help" ) == 0 )
				return help_handler;
			if( strcmp( str, "--dump" ) == 0 )
				return dump_handler;
		} break;
		case 7: {
			if( strcmp( str, "--input" ) == 0 )
				return input_handler;
		} break;
		case 8: {
			if( strcmp( str, "--output" ) == 0 )
				return output_handler;
			DFLY1_ (
			if( strcmp( str, "--pad-by" ) == 0 )
				return pad_by_handler;
			if( strcmp( str, "--pad-to" ) == 0 )
				return pad_to_handler;
			)
		} break;
		case 9: {
			if( strcmp( str, "--encrypt" ) == 0 )
				return encrypt_handler;
			if( strcmp( str, "--decrypt" ) == 0 )
				return decrypt_handler;
			if( strcmp( str, "--entropy" ) == 0 )
				return entropy_handler;
			DFLY1_ (
			if( strcmp( str, "--use-phi" ) == 0 )
				return use_phi_handler;
			)
		} break;
		DFLY1_ (
		case 12: {
			if( strcmp( str, "--min-memory" ) == 0 )
				return min_memory_handler;
			if( strcmp( str, "--max-memory" ) == 0 )
				return max_memory_handler;
			if( strcmp( str, "--use-memory" ) == 0 )
				return use_memory_handler;
			if( strcmp( str, "--iterations" ) == 0 )
				return iterations_handler;
		} break;
		)
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

Shim_Arg_Parser_t *
arg_processor (char const * str, void * SHIM_RESTRICT v_ctx) {
	int type = shim_argtype( str );
	switch( type ) {
		case SHIM_ARGTYPE_SHORT:
			return short_parser;
		case SHIM_ARGTYPE_LONG:
			return long_parser;
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

#define HANDLER_(prefix) \
	void \
	prefix##_handler (char ** str_arr, int const count, void * SHIM_RESTRICT v_ctx)

static void
set_mode_ (Threecrypt * ctx, int mode) {
	if( ctx->mode != THREECRYPT_MODE_NONE )
		SHIM_ERRX ("Error: 3crypt mode already set!\n");
	ctx->mode = mode;
}

HANDLER_ (h) {
	print_help();
	exit( EXIT_SUCCESS );
}
HANDLER_ (e) {
	set_mode_( (Threecrypt *)v_ctx, THREECRYPT_MODE_SYMMETRIC_ENC );
}
HANDLER_ (d) {
	set_mode_( (Threecrypt *)v_ctx, THREECRYPT_MODE_SYMMETRIC_DEC );
}
HANDLER_ (D) {
	set_mode_( (Threecrypt *)v_ctx, THREECRYPT_MODE_DUMP );
}
static size_t
get_fname_ (char ** SHIM_RESTRICT str_arr,
	    char ** SHIM_RESTRICT target,
	    int const count)
{
	if( *target )
		SHIM_ERRX ("Error: Already specified input file as %s\n", *target);
	if( count >= 2 ) {
		char const * fname = str_arr[ 1 ];
		if( fname ) {
			size_t fname_buf_size = strlen( fname ) + 1;
			(*target) = (char *)shim_checked_malloc( fname_buf_size );
			memcpy( *target, fname, fname_buf_size );
			str_arr[ 1 ] = NULL;
			return fname_buf_size - 1;
		}
	}
	return 0;
}
HANDLER_ (i) {
	Threecrypt * ctx = (Threecrypt *)v_ctx;
	ctx->input_filename_size = get_fname_( str_arr, &ctx->input_filename, count );
}
HANDLER_ (o) {
	Threecrypt * ctx = (Threecrypt *)v_ctx;
	ctx->output_filename_size = get_fname_( str_arr, &ctx->output_filename, count );
}
HANDLER_ (E) {
	((Threecrypt *)v_ctx)->catena_input.supplement_entropy = true;
}
#ifdef THREECRYPT_DRAGONFLY_V1_H

typedef uint8_t  Dragonfly_V1_U8_Func_t  (char const * SHIM_RESTRICT, int const);

static uint8_t
get_dfly_v1_u8_param_ (char ** str_arr, int const count,
		       Dragonfly_V1_U8_Func_t * dfly_f)
{
	uint8_t param = 0;
	if( count >= 2 ) {
		char const * mem_str = str_arr[ 1 ];
		if( mem_str ) {
			param = dfly_f( mem_str, strlen( mem_str ) );
			str_arr[ 1 ] = NULL;
		}
	}
	return param;
}
HANDLER_ (min_memory) {
	uint8_t memory = get_dfly_v1_u8_param_( str_arr, count, dfly_v1_parse_memory );
	if( memory )
		((Threecrypt *)v_ctx)->catena_input.g_low = memory;
}
HANDLER_ (max_memory) {
	uint8_t memory = get_dfly_v1_u8_param_( str_arr, count, dfly_v1_parse_memory );
	if( memory )
		((Threecrypt *)v_ctx)->catena_input.g_high = memory;
}
HANDLER_ (use_memory) {
	uint8_t memory = get_dfly_v1_u8_param_( str_arr, count, dfly_v1_parse_memory );
	if( memory ) {
		((Threecrypt *)v_ctx)->catena_input.g_low = memory;
		((Threecrypt *)v_ctx)->catena_input.g_high = memory;
	}
}
HANDLER_ (iterations) {
	uint8_t iterations = get_dfly_v1_u8_param_( str_arr, count, dfly_v1_parse_iterations );
	if( iterations )
		((Threecrypt *)v_ctx)->catena_input.lambda = iterations;
}
static uint64_t
get_dfly_v1_padding_ (char ** str_arr, int const count) {
	uint64_t padding = 0;
	if( count >= 2 ) {
		char const * mem_str = str_arr[ 1 ];
		if( mem_str ) {
			padding = dfly_v1_parse_padding( mem_str, strlen( mem_str ) );
			str_arr[ 1 ] = NULL;
		}
	}
	return padding;
}
HANDLER_ (pad_by) {
	uint64_t padding = get_dfly_v1_padding_( str_arr, count );
	if( padding )
		((Threecrypt *)v_ctx)->catena_input.padding_bytes = padding;
}
HANDLER_ (pad_to) {
	pad_by_handler( str_arr, count, v_ctx );
	((Threecrypt *)v_ctx)->catena_input.padding_mode = SYMM_COMMON_PAD_MODE_TARGET;
}
HANDLER_ (use_phi) {
	((Threecrypt *)v_ctx)->catena_input.use_phi = UINT8_C (0x01);
}
#endif /* ifdef THREECRYPT_DRAGONFLY_V1_H */
