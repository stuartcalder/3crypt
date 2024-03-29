#include "CommandLineArg.h"

#ifdef THREECRYPT_EXTERN_STRICT_ARG_PROCESSING
 #define HANDLE_INVALID_ARG_(Arg) SSC_errx("Error: Invalid argument: %s\n", Arg)
#else
 #define HANDLE_INVALID_ARG_(Arg) /* Nil. */
#endif

#define R_ SSC_RESTRICT

static const char* const mode_strings[THREECRYPT_MODE_MCOUNT] = {
  "None", "Encrypt", "Decrypt", "Dump"
};

typedef Threecrypt_Mode_t Mode_t;

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* Set the mode. Disallow setting the mode after it's already been set. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
static int
set_mode_(
 Threecrypt* R_ ctx,
 Mode_t         mode,
 char* R_       str,
 int            offset)
{
  SSC_assertMsg((ctx->mode == THREECRYPT_MODE_NONE), "Error: 3crypt mode already set to %s!\n", mode_strings[ctx->mode]);
  ctx->mode = mode;
  return SSC_1opt(str[offset]);
}
/*=========================================================================================================================*/

int decrypt_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  return set_mode_((Threecrypt*)state, THREECRYPT_MODE_SYMMETRIC_DEC, argv[0], offset);
}

int dump_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  return set_mode_((Threecrypt*)state, THREECRYPT_MODE_DUMP, argv[0], offset);
}

int encrypt_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  return set_mode_((Threecrypt*)state, THREECRYPT_MODE_SYMMETRIC_ENC, argv[0], offset);
}

int entropy_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.supplement_entropy = true;
  return SSC_1opt(argv[0][offset]);
}

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
/* Search through the C-String @s of length @len for an '=' char.
 * if found return the index of the first detected '=', otherwise return EQ_NOT_FOUND_. */
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
#define EQ_NOT_FOUND_ (-1)
static int
find_eq_(const char* R_ s, const int len)
{
  for (int i = 0; i < len; ++i) {
    if (s[i] == '=')
      return i;
  }
  return EQ_NOT_FOUND_;
}
/*=========================================================================================================================*/

int help_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  print_help(ap.to_read);
  exit(EXIT_SUCCESS);
  return 0; /* Suppress warnings about no return value. */
}

int input_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  SSC_assertMsg((ctx->input_filename == SSC_NULL), "Error: Already specified %s as %s!\n", "input file", ctx->input_filename);
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  if (ap.to_read) {
    ctx->input_filename = (char*)SSC_mallocOrDie(ap.size + 1);
    ctx->input_filename_size = ap.size;
    memcpy(ctx->input_filename, ap.to_read, ap.size + 1);
  }
  return ap.consumed;
}

#ifdef PPQ_DRAGONFLY_V1_H
typedef uint8_t Dfly_V1_U8_f(const char* R_, const int);

static uint8_t
get_dfly_v1_u8_param_(
 SSC_ArgParser* R_ ap,
 Dfly_V1_U8_f*     dfly)
{
  uint8_t param = 0;
  if (ap->to_read)
    param = dfly(ap->to_read, ap->size);
  return param;
}

static uint64_t
get_dfly_v1_padding_(SSC_ArgParser* ap)
{
  uint64_t padding = 0;
  if (ap->to_read)
    padding = dfly_v1_parse_padding(ap->to_read, ap->size);
  return padding;
}

int iterations_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  uint8_t iterations = get_dfly_v1_u8_param_(&ap, dfly_v1_parse_iterations);
  Threecrypt* ctx = (Threecrypt*)state;
  if (iterations)
    ctx->input.lambda = iterations;
  return ap.consumed;
}

int max_memory_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&ap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory)
    ctx->input.g_high = memory;
  return ap.consumed;
}

int min_memory_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&ap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory)
    ctx->input.g_low = memory;
  return ap.consumed;
}
#endif /* ! PPQ_DRAGONFLY_V1_H */

int output_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  SSC_assertMsg((ctx->output_filename == NULL), "Error: Already specified %s as %s!\n", "output file", ctx->output_filename);
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  if (ap.to_read) {
    ctx->output_filename = (char*)SSC_mallocOrDie(ap.size + 1);
    ctx->output_filename_size = ap.size;
    memcpy(ctx->output_filename, ap.to_read, ap.size + 1);
  }
  return ap.consumed;
}

#ifdef PPQ_DRAGONFLY_V1_H

int pad_as_if_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.padding_mode = PPQ_COMMON_PAD_MODE_ASIF;
  return pad_by_argproc(argc, argv, offset, ctx);
}

int pad_by_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  uint64_t padding = get_dfly_v1_padding_(&ap);
  Threecrypt* ctx = (Threecrypt*)state;
  if (padding)
    ctx->input.padding_bytes = padding;
  return ap.consumed;
}

int pad_to_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.padding_mode = PPQ_COMMON_PAD_MODE_TARGET;
  return pad_by_argproc(argc, argv, offset, ctx);
}

int use_memory_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&ap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory) {
    ctx->input.g_low  = memory;
    ctx->input.g_high = memory;
  }
  return ap.consumed;
}

int use_phi_argproc(const int argc, char** R_ argv, const int offset, void* R_ state)
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.use_phi = UINT8_C(0x01);
  return 0;
}

#endif /* ! ifdef PPQ_DRAGONFLY_V1_H */
