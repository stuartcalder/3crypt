#include "args.h"

#ifdef THREECRYPT_EXTERN_STRICT_ARG_PROCESSING
#  define HANDLE_INVALID_ARG_(arg) Base_errx("Error: Invalid argument: %s\n", arg)
#else
#  define HANDLE_INVALID_ARG_(arg) /* Nil. */
#endif

#define R_(p)		p BASE_RESTRICT
#define ARG_PROC_(name) int name##_argproc(const int argc, R_(char**) argv, const int offset, R_(void*) state)
#define ARGS_ (const int argc, R_(char**) argv, const int offset, R_(void*) state)

static const char* const mode_strings[THREECRYPT_MODE_MCOUNT] = { "None", "Encrypt", "Decrypt", "Dump" };

static int
set_mode_
(R_(Threecrypt*)   ctx,
 Threecrypt_Mode_t mode,
 R_(char*)         str,
 int               offset)
{
  Base_assert_msg((ctx->mode == THREECRYPT_MODE_NONE), "Error: 3crypt mode already set to %s!\n", mode_strings[ctx->mode]);
  ctx->mode = mode;
  return Base_1opt(str[offset]);
}

int
decrypt_argproc
ARGS_
{ return set_mode_((Threecrypt*)state, THREECRYPT_MODE_SYMMETRIC_DEC, argv[0], offset); }

int
dump_argproc
ARGS_
{ return set_mode_((Threecrypt*)state, THREECRYPT_MODE_DUMP, argv[0], offset); }

int
encrypt_argproc
ARGS_
{ return set_mode_((Threecrypt*)state, THREECRYPT_MODE_SYMMETRIC_ENC, argv[0], offset); }

int
entropy_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.supplement_entropy = true;
  return Base_1opt(argv[0][offset]);
}

#define EQ_NOT_FOUND_ (-1)
static int
find_eq_
(R_(const char*) s,
 const int       len)
{
  for (int i = 0; i < len; ++i) {
    if (s[i] == '=')
      return i;
  }
  return EQ_NOT_FOUND_;
}

int
help_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  print_help(bap.to_read);
  exit(EXIT_SUCCESS);
  return 0; /* Suppress warnings about no return value. */
}

int
input_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  Base_assert_msg((ctx->input_filename == NULL), "Error: Already specified %s as %s!\n", "input file", ctx->input_filename);
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  if (bap.to_read) {
    ctx->input_filename = (char*)Base_malloc_or_die(bap.size + 1);
    ctx->input_filename_size = bap.size;
    memcpy(ctx->input_filename, bap.to_read, bap.size + 1);
  }
  return bap.consumed;
}

#ifdef SKC_DRAGONFLY_V1_H
typedef uint8_t Dfly_V1_U8_f (R_(const char*), const int);

static uint8_t
get_dfly_v1_u8_param_
(R_(Base_Arg_Parser*) bap,
Dfly_V1_U8_f*         dfly)
{
  uint8_t param = 0;
  if (bap->to_read)
    param = dfly(bap->to_read, bap->size);
  return param;
}

static uint64_t
get_dfly_v1_padding_
(Base_Arg_Parser* bap)
{
  uint64_t padding = 0;
  if (bap->to_read)
    padding = dfly_v1_parse_padding(bap->to_read, bap->size);
  return padding;
}

int
iterations_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  uint8_t iterations = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_iterations);
  Threecrypt* ctx = (Threecrypt*)state;
  if (iterations)
    ctx->input.lambda = iterations;
  return bap.consumed;
}

int
max_memory_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory)
    ctx->input.g_high = memory;
  return bap.consumed;
}

int
min_memory_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory)
    ctx->input.g_low = memory;
  return bap.consumed;
}
#endif /* ! SKC_DRAGONFLY_V1_H */

int
output_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  Base_assert_msg((ctx->output_filename == NULL), "Error: Already specified %s as %s!\n", "output file", ctx->output_filename);
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  if (bap.to_read) {
    ctx->output_filename = (char*)Base_malloc_or_die(bap.size + 1);
    ctx->output_filename_size = bap.size;
    memcpy(ctx->output_filename, bap.to_read, bap.size + 1);
  }
  return bap.consumed;
}

#ifdef SKC_DRAGONFLY_V1_H

int
pad_as_if_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.padding_mode = SKC_COMMON_PAD_MODE_ASIF;
  return pad_by_argproc(argc, argv, offset, ctx);
}

int
pad_by_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  uint64_t padding = get_dfly_v1_padding_(&bap);
  Threecrypt* ctx = (Threecrypt*)state;
  if (padding)
    ctx->input.padding_bytes = padding;
  return bap.consumed;
}

int
pad_to_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.padding_mode = SKC_COMMON_PAD_MODE_TARGET;
  return pad_by_argproc(argc, argv, offset, ctx);
}

int
use_memory_argproc
ARGS_
{
  Base_Arg_Parser bap;
  Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
  uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
  Threecrypt* ctx = (Threecrypt*)state;
  if (memory) {
    ctx->input.g_low  = memory;
    ctx->input.g_high = memory;
  }
  return bap.consumed;
}

int
use_phi_argproc
ARGS_
{
  Threecrypt* ctx = (Threecrypt*)state;
  ctx->input.use_phi = UINT8_C(0x01);
  return 0;
}
#endif /* ! ifdef SKC_DRAGONFLY_V1_H */
