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
	char * const temp = (char *)shim_enforce_malloc(size + 1);
	memcpy(temp, mem_str, (size + 1));
	for (int i = 0; i < size; ++i) {
		switch (toupper((unsigned char)mem_str[i])) {
			case 'K':
				multiplier = (KIBIBYTE_ / 64);
				goto GoTo_have_multiplier;
			case 'M':
				multiplier = (MEBIBYTE_ / 64);
				goto GoTo_have_multiplier;
			case 'G':
				multiplier = (GIBIBYTE_ / 64);
				goto GoTo_have_multiplier;
			default:
				shim_assert_msg(isdigit((unsigned char)mem_str[i]), "Dragonfly_V1 Error: Invalid memory string.\n");
		}
	}
GoTo_have_multiplier:
	num_digits = shim_shift_left_digits(temp, size);
	shim_assert_msg(num_digits, "Dragonfly_V1 Error: No number supplied with memory-usage specification!\n");
#define BYTE_MAX_	UINT64_C (10000)
#define KIBIBYTE_MAX_	UINT64_C (17592186044416)
#define MEBIBYTE_MAX_	UINT64_C (17179869184)
#define GIBIBYTE_MAX_	UINT64_C (16777216)
#define INVALID_MEM_PARAM_	"Dragonfly_V1 Error: Specified memory parameter digits (%d)\n"
	uint64_t digit_count_limit = 0;
	switch (multiplier) {
		case                1: digit_count_limit = BYTE_MAX_;
		case (KIBIBYTE_ / 64): digit_count_limit = KIBIBYTE_MAX_;
		case (MEBIBYTE_ / 64): digit_count_limit = MEBIBYTE_MAX_;
		case (GIBIBYTE_ / 64): digit_count_limit = GIBIBYTE_MAX_;
	}
	shim_assert_msg(num_digits <= digit_count_limit, INVALID_MEM_PARAM_, num_digits);
	requested_bytes = (uint64_t)strtoumax(temp, NULL, 10);
	free(temp);
	requested_bytes *= multiplier;
	shim_assert_msg(requested_bytes, "Dragonfly_V1 Error: Zero memory requested?\n");
	uint64_t mask = UINT64_C(0x8000000000000000);
	uint8_t garlic = 63;
	while (!(mask & requested_bytes)) {
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
	memcpy(temp, iter_str, (size + 1));
	int num_digits = shim_shift_left_digits(temp, size);
	shim_assert_msg(num_digits > 0 && num_digits < 4, INVALID_ITER_COUNT_);
	int it = atoi(temp);
	free(temp);
	shim_assert_msg(it > 1 && it < 255, INVALID_ITER_COUNT_);
	return (uint8_t)it;
}

uint64_t
dfly_v1_parse_padding (char const * SHIM_RESTRICT pad_str,
		       int const		  size)
{
	char * const temp = (char *)shim_enforce_malloc(size + 1);
	memcpy(temp, pad_str, (size + 1));
	uint64_t multiplier = 1;
	for (int i = 0; i < size; ++i) {
		switch (toupper((unsigned char)pad_str[i])) {
			case 'K':
				multiplier = KIBIBYTE_;
				goto GoTo_have_multiplier;
			case 'M':
				multiplier = MEBIBYTE_;
				goto GoTo_have_multiplier;
			case 'G':
				multiplier = GIBIBYTE_;
				goto GoTo_have_multiplier;
		}
	}
	int num_digits;
GoTo_have_multiplier:
	num_digits = shim_shift_left_digits(temp, size);
	shim_assert_msg(num_digits, "Dragonfly_V1_Error: Asked for padding, without providing a random number of padding bytes.\n");
	uintmax_t pad = strtoumax(temp, NULL, 10);
	free(temp);
	return ((uint64_t)pad) * multiplier;
}
