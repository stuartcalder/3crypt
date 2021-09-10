#include "args.h"

#ifdef THREECRYPT_EXTERN_STRICT_ARG_PROCESSING
#  define HANDLE_INVALID_ARG_(arg) Base_errx("Error: Invalid argument: %s\n", arg)
#else
#  define HANDLE_INVALID_ARG_(arg) /* Nil. */
#endif

#define R_(p)		p BASE_RESTRICT
#define ARG_PROC_(name) int name##_argproc(const int argc, R_(char**) argv, const int offset, R_(void*) state)
#define CTX_(v)		((Threecrypt*)v)

static const char* const mode_strings[THREECRYPT_NUM_MODE_ENUMS] = { "None", "Encrypt", "Decrypt", "Dump" };

static int set_mode_(R_(Threecrypt*) ctx, int mode, R_(char*) str, int offset) {
	Base_assert_msg((ctx->mode == THREECRYPT_MODE_NONE), "Error: 3crypt mode already set to \"%s\"!\n", mode_strings[ctx->mode]);
	ctx->mode = mode;
	return Base_1opt(str[offset]);
}

ARG_PROC_(decrypt) { return set_mode_(CTX_(state), THREECRYPT_MODE_SYMMETRIC_DEC, argv[0], offset); }
ARG_PROC_(dump)    { return set_mode_(CTX_(state), THREECRYPT_MODE_DUMP         , argv[0], offset); }
ARG_PROC_(encrypt) { return set_mode_(CTX_(state), THREECRYPT_MODE_SYMMETRIC_ENC, argv[0], offset); }
ARG_PROC_(entropy) {
	CTX_(state)->input.supplement_entropy = true;
	return Base_1opt(argv[0][offset]);
}
ARG_PROC_(help) {
	print_help();
	exit(EXIT_SUCCESS);
	return 0;
}
ARG_PROC_(input) {
	Base_assert_msg((!CTX_(state)->input_filename), "Error: Already specified %s as %s!\n", "input file", CTX_(state)->input_filename);
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	if (bap.to_read) {
		CTX_(state)->input_filename = (char*)Base_malloc_or_die(bap.size + 1);
		CTX_(state)->input_filename_size = bap.size;
		memcpy(CTX_(state)->input_filename, bap.to_read, bap.size + 1);
	}
	return bap.consumed;
}
#ifdef SKC_DRAGONFLY_V1_H
typedef uint8_t Dfly_V1_U8_f (R_(const char*), const int);
static uint8_t get_dfly_v1_u8_param_(R_(Base_Arg_Parser*) bap, Dfly_V1_U8_f* dfly) {
	uint8_t param = 0;
	if (bap->to_read)
		param = dfly(bap->to_read, bap->size);
	return param;
}
static uint64_t get_dfly_v1_padding_(Base_Arg_Parser* bap) {
	uint64_t padding = 0;
	if (bap->to_read)
		padding = dfly_v1_parse_padding(bap->to_read, bap->size);
	return padding;
}
ARG_PROC_(iterations) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	uint8_t iterations = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_iterations);
	if (iterations)
		CTX_(state)->input.lambda = iterations;
	return bap.consumed;
}
ARG_PROC_(max_memory) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
	if (memory)
		CTX_(state)->input.g_high = memory;
	return bap.consumed;
}
ARG_PROC_(min_memory) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
	if (memory)
		CTX_(state)->input.g_low = memory;
	return bap.consumed;
}
#endif /* ! SKC_DRAGONFLY_V1_H */
ARG_PROC_(output) {
	Base_assert_msg((!CTX_(state)->output_filename), "Error: Already specified %s as %s!\n", "output file", CTX_(state)->output_filename);
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	if (bap.to_read) {
		CTX_(state)->output_filename = (char*)Base_malloc_or_die(bap.size + 1);
		CTX_(state)->output_filename_size = bap.size;
		memcpy(CTX_(state)->output_filename, bap.to_read, bap.size + 1);
	}
	return bap.consumed;
}
#ifdef SKC_DRAGONFLY_V1_H
ARG_PROC_(pad_as_if) {
	int consumed = pad_by_argproc(argc, argv, offset, state);
	CTX_(state)->input.padding_mode = SKC_COMMON_PAD_MODE_ASIF;
	return consumed;
}
ARG_PROC_(pad_by) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	uint64_t padding = get_dfly_v1_padding_(&bap);
	if (padding)
		CTX_(state)->input.padding_bytes = padding;
	return bap.consumed;
}
ARG_PROC_(pad_to) {
	int consumed = pad_by_argproc(argc, argv, offset, state);
	CTX_(state)->input.padding_mode = SKC_COMMON_PAD_MODE_TARGET;
	return consumed;
}
ARG_PROC_(use_memory) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0] + offset, argc, argv);
	uint8_t memory = get_dfly_v1_u8_param_(&bap, dfly_v1_parse_memory);
	if (memory) {
		CTX_(state)->input.g_low  = memory;
		CTX_(state)->input.g_high = memory;
	}
	return bap.consumed;
}
ARG_PROC_(use_phi) {
	CTX_(state)->input.use_phi = UINT8_C(0x01);
	return 0;
}
#endif
