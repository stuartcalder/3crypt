#include "args.h"

/* When Strict Arg Processing is enabled, invalid command-line arguments kill the program
 * instead of being silently ignored.
 */
#ifdef THREECRYPT_EXTERN_STRICT_ARG_PROCESSING
#  define HANDLE_INVALID_ARG_(arg) Base_errx("Error: Invalid argument: %s\n", arg)
#else
#  define HANDLE_INVALID_ARG_(arg) /* Nil. */
#endif

#define STR_EQ_(s0, s1)  (!strcmp(s0, s1))
#define STR_TO_F_(s, fn) if (STR_EQ_(str + 2, s)) return fn;

#ifdef SKC_DRAGONFLY_V1_H
#  define STR_TO_DFLY1_F_(s, fn) STR_TO_F_(s, fn)
#else
#  define STR_TO_DFLY1_F_(s, fn) /* Nil. */
#endif

#define R_(p) p BASE_RESTRICT

Base_Arg_Handler_f* short_parser (const char* str) {
	const size_t str_size = strlen(str);
	switch (str_size) {
		case 2: {
			switch (str[1]) {
				case 'h': return h_handler;
				case 'e': return e_handler;
				case 'd': return d_handler;
				case 'D': return D_handler;
				case 'i': return i_handler;
				case 'o': return o_handler;
				case 'E': return E_handler;
			}
		} break;
	}
	HANDLE_INVALID_ARG_(str);
	return NULL;
}

Base_Arg_Handler_f* long_parser (const char* str) {
	const size_t str_size = strlen(str) - 2;
	switch (str_size) {
		case 4:
			STR_TO_F_("help", help_handler);
			STR_TO_F_("dump", dump_handler);
			break;
		case 5:
			STR_TO_F_("input", input_handler);
			break;
		case 6:
			STR_TO_F_("output", output_handler);
			STR_TO_DFLY1_F_("pad-by", pad_by_handler);
			STR_TO_DFLY1_F_("pad-to", pad_to_handler);
			break;
		case 7:
			STR_TO_F_("encrypt", encrypt_handler);
			STR_TO_F_("decrypt", decrypt_handler);
			STR_TO_F_("entropy", entropy_handler);
			STR_TO_DFLY1_F_("use-phi", use_phi_handler);
			break;
		case 9:
			STR_TO_DFLY1_F_("pad-as-if", pad_as_if_handler);
			break;
		case 10:
			STR_TO_DFLY1_F_("min-memory", min_memory_handler);
			STR_TO_DFLY1_F_("max-memory", max_memory_handler);
			STR_TO_DFLY1_F_("use-memory", use_memory_handler);
			STR_TO_DFLY1_F_("iterations", iterations_handler);
			break;
	}
	HANDLE_INVALID_ARG_(str);
	return NULL;
}

Base_Arg_Parser_f* arg_processor (const char* str, R_(void*) v_ctx) {
	const int type = Base_argtype(str);
	switch (type) {
	case BASE_ARGTYPE_SHORT: return short_parser;
	case BASE_ARGTYPE_LONG:  return long_parser;
	}
	HANDLE_INVALID_ARG_(str);
	return NULL;
}

#define HANDLER_(pfx) \
  void pfx##_handler (char** str_arr, const int count, void* BASE_RESTRICT v_ctx)
#define CTX_ \
  ((Threecrypt*)v_ctx)

static const char* mode_strings[THREECRYPT_NUM_MODE_ENUMS] = {
	"None", "Encrypt", "Decrypt", "Dump"
};

static void set_mode_ (Threecrypt* ctx, int mode) {
	Base_assert_msg(ctx->mode == THREECRYPT_MODE_NONE, "Error: 3crypt mode already set to \"%s\".\n", mode_strings[ctx->mode]);
	ctx->mode = mode;
}

HANDLER_(h) { print_help(); exit(EXIT_SUCCESS); }
HANDLER_(e) { set_mode_(CTX_, THREECRYPT_MODE_SYMMETRIC_ENC); }
HANDLER_(d) { set_mode_(CTX_, THREECRYPT_MODE_SYMMETRIC_DEC); }
HANDLER_(D) { set_mode_(CTX_, THREECRYPT_MODE_DUMP); }

static size_t get_fname_ (R_(char**)      str_arr,
                          R_(char**)      target,
			  const int       count,
			  R_(const char*) error_str)
{
	Base_assert_msg(!(*target), error_str, *target);
	if (count >= 2) {
		const char* const fname = str_arr[1];
		if (fname) {
			const size_t fname_buf_size = strlen(fname) + 1;
			*target = (char*)Base_malloc_or_die(fname_buf_size);
			memcpy(*target, fname, fname_buf_size);
			str_arr[1] = NULL;
			return fname_buf_size - 1;
		}
	}
	return 0;
}

HANDLER_(i) {
	CTX_->input_filename_size = get_fname_(str_arr, &CTX_->input_filename, count, "Error: Already specified input file as %s\n");
}
HANDLER_(o) {
	CTX_->output_filename_size = get_fname_(str_arr, &CTX_->output_filename, count, "Error: Already specified output file as %s\n");
}
HANDLER_(E) {
	CTX_->input.supplement_entropy = true;
}
#ifdef THREECRYPT_DRAGONFLY_V1_H

typedef uint8_t Dragonfly_V1_U8_f (R_(const char*), const int);

static uint8_t get_dfly_v1_u8_param_ (char** str_arr, const int count, Dragonfly_V1_U8_f* dfly_f) {
	uint8_t param = 0;
	if (count >= 2) {
		const char* const mem_str = str_arr[1];
		if (mem_str) {
			param = dfly_f(mem_str, strlen(mem_str));
			str_arr[1] = NULL;
		}
	}
	return param;
}

HANDLER_(min_memory) {
	uint8_t memory = get_dfly_v1_u8_param_(str_arr, count, dfly_v1_parse_memory);
	if (memory)
		CTX_->input.g_low = memory;
}
HANDLER_(max_memory) {
	uint8_t memory = get_dfly_v1_u8_param_(str_arr, count, dfly_v1_parse_memory);
	if (memory)
		CTX_->input.g_high = memory;
}
HANDLER_(use_memory) {
	uint8_t memory = get_dfly_v1_u8_param_(str_arr, count, dfly_v1_parse_memory);
	if (memory) {
		CTX_->input.g_low  = memory;
		CTX_->input.g_high = memory;
	}
}
HANDLER_(iterations) {
	uint8_t iterations = get_dfly_v1_u8_param_(str_arr, count, dfly_v1_parse_iterations);
	if (iterations)
		CTX_->input.lambda = iterations;
}
static uint64_t get_dfly_v1_padding_ (char** str_arr, const int count) {
	uint64_t padding = 0;
	if (count >= 2) {
		const char* const mem_str = str_arr[1];
		if (mem_str) {
			padding = dfly_v1_parse_padding(mem_str, strlen(mem_str));
			str_arr[1] = NULL;
		}
	}
	return padding;
}
HANDLER_(pad_by) {
	uint64_t padding = get_dfly_v1_padding_(str_arr, count);
	if (padding)
		CTX_->input.padding_bytes = padding;
}
HANDLER_(pad_to) {
	pad_by_handler(str_arr, count, v_ctx);
	CTX_->input.padding_mode = SKC_COMMON_PAD_MODE_TARGET;
}
HANDLER_(pad_as_if) {
	pad_by_handler(str_arr, count, v_ctx);
	CTX_->input.padding_mode = SKC_COMMON_PAD_MODE_ASIF;
}
HANDLER_(use_phi) {
	CTX_->input.use_phi = UINT8_C(0x01);
}
#endif /* ifdef THREECRYPT_DRAGONFLY_V1_H */
