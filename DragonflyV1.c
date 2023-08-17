#include <ctype.h>
#include <string.h>
#include <SSC/String.h>
#include <SSC/Operation.h>
#include "DragonflyV1.h"

#define R_ SSC_RESTRICT

#define KIBIBYTE_ UINT64_C(1024)
#define MEBIBYTE_ (KIBIBYTE_ * KIBIBYTE_)
#define GIBIBYTE_ (MEBIBYTE_ * KIBIBYTE_)

#define KIBIBYTE_MUL_ (KIBIBYTE_ / 64)
#define MEBIBYTE_MUL_ (MEBIBYTE_ / 64)
#define GIBIBYTE_MUL_ (GIBIBYTE_ / 64)

uint8_t
dfly_v1_parse_memory(const char* R_ mem_str, const int size)
{
  uint64_t requested_bytes = 0;
  uint64_t multiplier = 1;
  int num_digits;
  char* const temp = (char*)SSC_mallocOrDie(size + 1);
  memcpy(temp, mem_str, size + 1);

  for (int i = 0; i < size; ++i) {
    switch (toupper((unsigned char)mem_str[i])) {
      case 'K':
        multiplier = KIBIBYTE_MUL_;
        goto have_multiplier;
      case 'M':
        multiplier = MEBIBYTE_MUL_;
        goto have_multiplier;
      case 'G':
        multiplier = GIBIBYTE_MUL_;
        goto have_multiplier;
      default:
        /* If the character is not a 'K', 'M', or 'G' size designation force it to be a digit. */
        SSC_assertMsg(isdigit((unsigned char)mem_str[i]), "Dragonfly_V1 Error: Invalid memory string, '%s'!\n", mem_str);
    }
  }
have_multiplier:
  /* Shift all the digits to the beginning of the @temp string, and store the
   * number of digits in @num_digits. */
  num_digits = SSC_Cstr_shiftDigitsToFront(temp, size);
  SSC_assertMsg(num_digits, "Dragonfly_V1 Error: No number supplied with memory-usage specification!\n");
  #define BYTE_MAX_          UINT64_C(10000)
  #define KIBIBYTE_MAX_      UINT64_C(17592186044416)
  #define MEBIBYTE_MAX_      UINT64_C(17179869184)
  #define GIBIBYTE_MAX_      UINT64_C(16777216)
  #define INVALID_MEM_PARAM_ "Dragonfly_V1 Error: Specified memory parameter digits (%d)\n"
  uint64_t digit_count_limit = 0;
  switch (multiplier) {
    case 1:
      digit_count_limit = BYTE_MAX_;
      break;
    case KIBIBYTE_MUL_:
      digit_count_limit = KIBIBYTE_MAX_;
      break;
    case MEBIBYTE_MUL_:
      digit_count_limit = MEBIBYTE_MAX_;
      break;
    case GIBIBYTE_MUL_:
      digit_count_limit = GIBIBYTE_MAX_;
      break;
  }
  SSC_assertMsg(num_digits <= digit_count_limit, INVALID_MEM_PARAM_, num_digits);
  requested_bytes = (uint64_t)strtoumax(temp, SSC_NULL, 10);
  free(temp);
  requested_bytes *= multiplier;
  SSC_assertMsg(requested_bytes, "DragonflY_V1 Error: Zero memory requested?\n");
  uint64_t mask = UINT64_C(0x8000000000000000);
  uint8_t garlic = 63;
  while (!(mask & requested_bytes)) {
    mask >>= 1;
    --garlic;
  }
  return garlic;
}

uint8_t
dfly_v1_parse_iterations (const char* R_ iter_str, const int size)
{
  #define INVALID_ITER_COUNT_ "Dragonfly_V1 Error: Invalid iteration count.\n"
  char* const temp = (char*)SSC_mallocOrDie(size + 1);
  memcpy(temp, iter_str, (size + 1));
  int num_digits = SSC_Cstr_shiftDigitsToFront(temp, size);
  SSC_assertMsg(num_digits >= 1 && num_digits <= 3, INVALID_ITER_COUNT_);
  int it = atoi(temp);
  free(temp);
  SSC_assertMsg(it >= 1 && it <= 255, INVALID_ITER_COUNT_);
  return (uint8_t)it;
}

uint64_t
dfly_v1_parse_padding(const char* R_ pad_str, const int size)
{
  char* const temp = (char*)SSC_mallocOrDie(size + 1);
  memcpy(temp, pad_str, (size + 1));
  uint64_t multiplier = 1;
  for (int i = 0; i < size; ++i) {
    switch (toupper((unsigned char)pad_str[i])) {
      case 'K':
        multiplier = KIBIBYTE_;
        goto have_multiplier;
      case 'M':
        multiplier = MEBIBYTE_;
        goto have_multiplier;
      case 'G':
        multiplier = GIBIBYTE_;
        goto have_multiplier;
    }
  }
  int num_digits;
have_multiplier:
  num_digits = SSC_Cstr_shiftDigitsToFront(temp, size);
  SSC_assertMsg(num_digits > 0, "Dragonfly_V1_Error: Asked for padding, without providing the desired number of padding bytes.\n");
  uint64_t pad = (uint64_t)strtoumax(temp, NULL, 10);
  free(temp);
  return pad * multiplier;
}
