#include "dragonfly_v1.h"
#include <shim/strings.h>
#include <shim/operations.h>
#include <ctype.h>
#include <string.h>

#define KIBIBYTE_	1024
#define MEBIBYTE_	(KIBIBYTE_ * 1024)
#define GIBIBYTE_	(MEBIBYTE_ * 1024)

uint8_t
dfly_v1_parse_memory (char const * SHIM_RESTRICT mem_str,
		      int const                  size)
{
	uint64_t requested_bytes = 0;
	uint64_t multiplier = 1;
	int num_digits;
	char * const temp = (char *)shim_enforce_malloc( size + 1 );
	memcpy( temp, mem_str, (size + 1) );
	for( int i = 0; i < size; ++i ) {
		switch( toupper( (unsigned char)mem_str[ i ] ) ) {
			case 'K':
				multiplier = (KIBIBYTE_ / 64);
				goto Have_Mul_Label;
			case 'M':
				multiplier = (MEBIBYTE_ / 64);
				goto Have_Mul_Label;
			case 'G':
				multiplier = (GIBIBYTE_ / 64);
				goto Have_Mul_Label;
			default:
				if( !isdigit( (unsigned char)mem_str[ i ] ) )
					SHIM_ERRX ("Dragonfly_V1 Error: Invalid memory string.\n");
		}
	}
Have_Mul_Label:
	num_digits = shim_shift_left_digits( temp, size );
	if( num_digits == 0 )
		SHIM_ERRX ("Dragonfly_V1 Error: No number supplied with memory-usage specification!\n");
#define BYTE_MAX_	UINT64_C (1000)
#define KIBIBYTE_MAX_	UINT64_C (17592186044416)
#define MEBIBYTE_MAX_	UINT64_C (17179869184)
#define GIBIBYTE_MAX_	UINT64_C (16777216)
#define INVALID_MEM_PARAM_	"Dragonfly_V1 Error: Specified memory parameter digits (%d)\n"
	uint64_t digit_count_limit = 0;
	switch( multiplier ) {
		case 1: {
			digit_count_limit = BYTE_MAX_;
		} break;
		case (KIBIBYTE_ / 64): {
			digit_count_limit = KIBIBYTE_MAX_;
		} break;
		case (MEBIBYTE_ / 64): {
			digit_count_limit = MEBIBYTE_MAX_;
		} break;
		case (GIBIBYTE_ / 64): {
			digit_count_limit = GIBIBYTE_MAX_;
		} break;
	}
	if( num_digits > digit_count_limit )
		SHIM_ERRX (INVALID_MEM_PARAM_, num_digits);
	requested_bytes = (uint64_t)strtoumax( temp, NULL, 10 );
	free( temp );
	requested_bytes *= multiplier;
	if( !requested_bytes )
		SHIM_ERRX ("Dragonfly_V1 Error: Zero memory requested?\n");
	uint64_t mask = UINT64_C (0x8000000000000000);
	uint8_t garlic = 63;
	while( !(mask & requested_bytes) ) {
		mask >>= 1;
		--garlic;
	}
	return garlic;
}

uint8_t
dfly_v1_parse_iterations (char const * SHIM_RESTRICT iter_str,
			  int const                  size)
{
#define INVALID_ITER_COUNT_ "Dragonfly_V1 Error: Invalid iteration count.\n"
	char * const temp = (char *)shim_enforce_malloc( size + 1 );
	memcpy( temp, iter_str, (size + 1) );
	int num_digits = shim_shift_left_digits( temp, size );
	if( num_digits <= 0 || num_digits >= 4 )
		SHIM_ERRX (INVALID_ITER_COUNT_);
	int it = atoi( temp );
	free( temp );
	if( it < 1 || it > 255 )
		SHIM_ERRX (INVALID_ITER_COUNT_);
	return (uint8_t)it;
}

uint64_t
dfly_v1_parse_padding (char const * SHIM_RESTRICT pad_str,
		       int const		  size)
{
	char * const temp = (char *)shim_enforce_malloc( size + 1 );
	memcpy( temp, pad_str, (size + 1) );
	uint64_t multiplier = 1;
	for( int i = 0; i < size; ++i ) {
		switch( toupper( (unsigned char)pad_str[ i ] ) ) {
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
	int num_digits;
Have_Mul_L:
	num_digits = shim_shift_left_digits( temp, size );
	if( num_digits == 0 )
		SHIM_ERRX( "Dragonfly_V1 Error: Asked for padding, without providing a random number of padding bytes.\n");
	uintmax_t pad = strtoumax( temp, NULL, 10 );
	free( temp );
	return ((uint64_t)pad) * multiplier;
}
