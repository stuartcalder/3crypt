#include <ctype.h>

#include <SSC/MemLock.h>
#include <SSC/MemMap.h>
#include <SSC/Operation.h>
#include <SSC/Terminal.h>

#include "Threecrypt.h"
#include "CommandLineArg.h"

#ifdef SSC_MEMLOCK_H
 #define LOCK_INIT_                SSC_MemLock_Global_initHandled() /* Initialize the global memorylocking variable @SSC_Mlock_g. */
 #define LOCK_M_(Mem, Size)        SSC_MemLock_lockOrDie(Mem, Size) /* Lock @size bytes starting at @mem, or terminate the program. */
 #define ULOCK_M_(Mem, Size)       SSC_MemLock_unlockOrDie(Mem, Size) /* Unlock @size bytes starting at @mem, or terminate the program. */
 #define ALLOC_M_(Alignment, Size) SSC_alignedMalloc(Alignment, Size) /* Allocate @size bytes, along @alignment byte boundaries. */
 #define DEALLOC_M_(Mem)           SSC_alignedFree(Mem) /* Deallocate the aligned memory starting beginning at @mem. */
#else
 #define LOCK_INIT_                 /* Nil. */
 #define LOCK_M_(Mem_, Size_)       /* Nil. */
 #define ULOCK_M_(Mem_, Size_)      /* Nil. */
 #define ALLOC_M_(Alignment_, Size) malloc(Size) /* Allocate @size bytes. */
 #define DEALLOC_M_(Mem)            free(Mem)    /* Deallocate bytes starting at @mem. */
#endif

typedef PPQ_DragonflyV1Encrypt Encrypt_t;
typedef PPQ_DragonflyV1Decrypt Decrypt_t;

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
#if !THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
 #error "Dragonfly_V1 is the only supported method!"
#endif
                           "Dragonfly_V1 Encryption Options\n"
                           "-------------------------------\n"
                           "--min-memory  <number_bytes>[K|M|G]\tThe minimum amount of memory to consume during key-derivation. Minimum memory cost.\n"
                           "--max-memory  <number_bytes>[K|M|G]\tThe maximum amount of memory to consume during key-derivation. Maximum memory cost.\n"
                           "--use-memory <number_bytes>[K|M|G]\tThe precise amount of memory to consume during key-derivation. Precise memory cost.\n"
                           "    The more memory we use for key-derivation, the harder it will be to attack your password.\n"
                           "    Memory minimums and maximums are rounded down to the nearest power of 2.\n"
                           "--iterations <number>\tThe number of times to iterate the memory-hard function during key-derivation. Time cost.\n"
                           "--pad-by    <number_bytes>[K|M|G]\tThe number of padding bytes to add to the encrypted file, to obfuscate its size.\n"
                           "--pad-to    <number_bytes>[K|M|G]\tThe target number of bytes you want your encrypted file to be; Will fail if it's not big enough.\n"
                           "--pad-as-if <number_bytes>[K|M|G]\tAdd padding such that the encrypted file is the same size as an unpadded encrypted file of this size.\n"
                           "--use-phi\t\tWhether to enable the optional phi function.\n"
                           "    WARNING: The optional phi function hardens the key-derivation function against\n"
                           "    parallel adversaries, greatly increasing the work necessary to attack your\n"
                           "    password, but introduces the potential for cache-timing attacks...\n"
                           "    Do NOT use this feature unless you understand the security implications!\n";

static Threecrypt_Method_t
determine_crypto_method_(SSC_MemMap*);

static void
threecrypt_encrypt_(Threecrypt*);

static void
threecrypt_decrypt_(Threecrypt*);

static void
threecrypt_dump_(Threecrypt*);

#define ARG_ARR_SIZE_(Array, Type) ((sizeof(Array) / sizeof(Type)) - 1)

static const SSC_ArgLong longs[] = {
  SSC_ARGLONG_LITERAL(decrypt_argproc, "decrypt"),
  SSC_ARGLONG_LITERAL(dump_argproc,    "dump"),
  SSC_ARGLONG_LITERAL(encrypt_argproc, "encrypt"),
  SSC_ARGLONG_LITERAL(entropy_argproc, "entropy"),
  SSC_ARGLONG_LITERAL(help_argproc,    "help"),
  SSC_ARGLONG_LITERAL(input_argproc,   "input"),
  #if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
  SSC_ARGLONG_LITERAL(iterations_argproc, "iterations"),
  SSC_ARGLONG_LITERAL(max_memory_argproc, "max-memory"),
  SSC_ARGLONG_LITERAL(min_memory_argproc, "min-memory"),
  #endif
  SSC_ARGLONG_LITERAL(output_argproc, "output"),
  #if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
  SSC_ARGLONG_LITERAL(pad_as_if_argproc,  "pad-as-if"),
  SSC_ARGLONG_LITERAL(pad_by_argproc,     "pad-by"),
  SSC_ARGLONG_LITERAL(pad_to_argproc,     "pad-to"),
  SSC_ARGLONG_LITERAL(use_memory_argproc, "use-memory"),
  SSC_ARGLONG_LITERAL(use_phi_argproc,    "use-phi"),
  #endif
  SSC_ARGLONG_NULL_LITERAL
};
#define NUM_LONGS_ ARG_ARR_SIZE_(longs, SSC_ArgLong)

static const SSC_ArgShort shorts[] = {
  SSC_ARGSHORT_LITERAL(dump_argproc   , 'D'),
  SSC_ARGSHORT_LITERAL(entropy_argproc, 'E'),
  SSC_ARGSHORT_LITERAL(decrypt_argproc, 'd'),
  SSC_ARGSHORT_LITERAL(encrypt_argproc, 'e'),
  SSC_ARGSHORT_LITERAL(help_argproc,    'h'),
  SSC_ARGSHORT_LITERAL(input_argproc,   'i'),
  SSC_ARGSHORT_LITERAL(output_argproc,  'o'),
  SSC_ARGSHORT_NULL_LITERAL
};
#define NUM_SHORTS_ ARG_ARR_SIZE_(shorts, SSC_ArgShort)

void threecrypt(int argc, char** argv)
{
  /* Zero-Initialize the Threecrypt data
   * before processing the command-line arguments. */
  Threecrypt tcrypt = THREECRYPT_NULL_LITERAL;
  LOCK_INIT_; /* Initialize SSC_MLock_g, if we're going to use memory locking procedures. */
  SSC_assert(argc);
  SSC_processCommandLineArgs(argc - 1, argv + 1, NUM_SHORTS_, shorts, NUM_LONGS_, longs, &tcrypt, SSC_NULL);
  /* Error: No mode specified. User may have supplied input/output filenames but
   * never specified what action to perform. */
  SSC_assertMsg(tcrypt.mode != THREECRYPT_MODE_NONE, "Error: No mode specified.\n%s", Help_Suggestion);
  /* Error: Input file not specified. Mode supplied, input file not supplied. */
  SSC_assertMsg(tcrypt.input_filename != NULL, "Error: Input file was not specified.\n%s", Help_Suggestion);
  /* On OpenBSD, we call unveil with "r" so we're allowed to
   * read from the input file. */
  SSC_OPENBSD_UNVEIL(tcrypt.input_filename, "r");
  /* If the input file does not seem to exist, error out. */
  SSC_assertMsg(
   SSC_FilePath_exists(tcrypt.input_filename), "Error: The input file %s does not seem to exist.\n%s",
   tcrypt.input_filename, Help_Suggestion);
  /* Get the size of the input file, and store it in the input_map. */
  tcrypt.input_map.size = SSC_FilePath_getSizeOrDie(tcrypt.input_filename);
  switch (tcrypt.mode) {
  case THREECRYPT_MODE_SYMMETRIC_ENC: {
    /* We're encrypting. During encryption output filename need not be specified.
     * If it isn't explicitly specified, it is assumed to be "<input_filename>.3c" */
    if (!tcrypt.output_filename) {
      size_t const buf_size = tcrypt.input_filename_size + sizeof(".3c");
      tcrypt.output_filename = (char*)SSC_mallocOrDie(buf_size);
      tcrypt.output_filename_size = buf_size - 1;
      memcpy(tcrypt.output_filename, tcrypt.input_filename, tcrypt.input_filename_size);
      memcpy(tcrypt.output_filename + tcrypt.input_filename_size, ".3c", sizeof(".3c"));
    }
    /* On OpenBSD, we call unveil with "rwc" so we're allowed to
     * read/write/create the output file, then follow up with two
     * NULL pointers to prevent further calls to unveil. */
#define OPENBSD_UNVEIL_OUTPUT_(output_filename_v) SSC_OPENBSD_UNVEIL(output_filename_v, "rwc"); SSC_OPENBSD_UNVEIL(SSC_NULL, SSC_NULL)
    OPENBSD_UNVEIL_OUTPUT_(tcrypt.output_filename);
    /* If there is already a file with the specified output filename, error out. */
    SSC_assertMsg(
     !SSC_FilePath_exists(tcrypt.output_filename),
     "Error: The output file %s already seems to exist.\n", tcrypt.output_filename);
    threecrypt_encrypt_(&tcrypt);
  } break; /* THREECRYPT_MODE_SYMMETRIC_ENC */
  case THREECRYPT_MODE_SYMMETRIC_DEC: {
    /* We're decrypting. Output filename need not be specified if the input filename
     * ends in ".3c". */
    if (!tcrypt.output_filename) {
      /* Minimum size of filename is 1 char + ".3c", 4 characters.  */
      SSC_assertMsg(tcrypt.input_filename_size >= 4, "Error: No output file specified.\n");
      tcrypt.output_filename_size = tcrypt.input_filename_size - 3;
      SSC_assertMsg(
       !strcmp(tcrypt.input_filename + tcrypt.output_filename_size, ".3c"),
       "Error: No output file specified.\n");
      tcrypt.output_filename = (char*)SSC_mallocOrDie(tcrypt.output_filename_size + 1);
      memcpy(tcrypt.output_filename, tcrypt.input_filename, tcrypt.output_filename_size);
      tcrypt.output_filename[tcrypt.output_filename_size] = '\0';
    }
    OPENBSD_UNVEIL_OUTPUT_(tcrypt.output_filename);
    SSC_assertMsg(!SSC_FilePath_exists(tcrypt.output_filename),
     "Error: The output file %s already seems to exist.\n", tcrypt.output_filename);
    threecrypt_decrypt_(&tcrypt);
  } break; /* THREECRYPT_MODE_SYMMETRIC_DEC */
  case THREECRYPT_MODE_DUMP: {
    SSC_OPENBSD_UNVEIL(NULL, NULL);
    SSC_OPENBSD_PLEDGE("stdio rpath tty", NULL);
    threecrypt_dump_(&tcrypt);
  } break; /* THREECRYPT_MODE_DUMP */
  default:
    SSC_errx("Error: Invalid, unrecognized mode (%d)\n%s", tcrypt.mode, Help_Suggestion);
    break;
  } /* switch( tcrypt.mode ) */
  free(tcrypt.input_filename);
  free(tcrypt.output_filename);
}

Threecrypt_Method_t
determine_crypto_method_(SSC_MemMap* map)
{
  if (map->size < THREECRYPT_MIN_ID_STR_BYTES)
  return THREECRYPT_METHOD_NONE;
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
{
  SSC_STATIC_ASSERT(sizeof(PPQ_DRAGONFLY_V1_ID) >= THREECRYPT_MIN_ID_STR_BYTES, "Less than the minimum # of ID bytes.");
  SSC_STATIC_ASSERT(sizeof(PPQ_DRAGONFLY_V1_ID) <= THREECRYPT_MAX_ID_STR_BYTES, "More than the minimum # of ID bytes.");
  if (!memcmp(map->ptr, PPQ_DRAGONFLY_V1_ID, sizeof(PPQ_DRAGONFLY_V1_ID)))
    return THREECRYPT_METHOD_DRAGONFLY_V1;
}
#else
 #error "Only supported method!"
#endif
  return THREECRYPT_METHOD_NONE;
}

void threecrypt_encrypt_ (Threecrypt* ctx) {
  switch (ctx->input.padding_mode) {
  case PPQ_COMMON_PAD_MODE_TARGET: {
    uint64_t target = ctx->input.padding_bytes;
    SSC_assertMsg(
     target >= PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES,
     "Error: The --pad-to target (%" PRIu64 ") is too small!\n", target);
    SSC_assertMsg(
     (target - PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES) >= ctx->input_map.size,
     "Error: The input file size (%zu) is too large to --pad-to %" PRIu64 "\n",
     ctx->input_map.size, target);
    target -= ctx->input_map.size;
    target -= PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
    ctx->input.padding_bytes = target;
    ctx->input.padding_mode = PPQ_COMMON_PAD_MODE_ADD;
  } break;
  case PPQ_COMMON_PAD_MODE_ASIF: {
    uint64_t target = ctx->input.padding_bytes;
    SSC_assertMsg(target >= 1, "Error: The --pad-as-if target (%" PRIu64 ") is too small!\n", target);
    SSC_assertMsg(
     target >= ctx->input_map.size,
     "Error: The input file size (%zu) is too large to --pad-as-if %" PRIu64 "\n",
     ctx->input_map.size, target);
    target -= ctx->input_map.size;
    ctx->input.padding_bytes = target;
    ctx->input.padding_mode = PPQ_COMMON_PAD_MODE_ADD;
  } break;
  } /* ! switch(ctx->input.padding_mode) */
  ctx->input_map.file = SSC_FilePath_openOrDie(ctx->input_filename, true);
  SSC_MemMap_mapOrDie(&ctx->input_map, true);
  ctx->output_map.file = SSC_FilePath_createOrDie(ctx->output_filename);

#ifdef THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC
 #define DEFAULT_GARLIC_IMPL_(v) UINT8_C(v)
 #define DEFAULT_GARLIC_         DEFAULT_GARLIC_IMPL_(THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC)
  SSC_STATIC_ASSERT(THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC >   0, "Must be greater than 0");
  SSC_STATIC_ASSERT(THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC <= 63, "Must be less than 64");
#else
 #define DEFAULT_GARLIC_ UINT8_C(24)
#endif

  if (!ctx->input.g_low)
    ctx->input.g_low = DEFAULT_GARLIC_;
  if (!ctx->input.g_high)
    ctx->input.g_high = DEFAULT_GARLIC_;
  if (ctx->input.g_low > ctx->input.g_high)
    ctx->input.g_high = ctx->input.g_low;
  if (!ctx->input.lambda)
    ctx->input.lambda = UINT8_C(1);
  Encrypt_t* enc_p;
  SSC_assertMsg(
   (enc_p = (Encrypt_t*)ALLOC_M_(SSC_MemLock_Global.page_size, sizeof(Encrypt_t))) != SSC_NULL,
   "Error: Memory allocation failed!\n");
  PPQ_DragonflyV1Encrypt_init(enc_p);
  memcpy(&(enc_p->secret.input), &ctx->input, sizeof(ctx->input));
  SSC_secureZero(&ctx->input, sizeof(ctx->input));
  {
    SSC_Terminal_init();
    memset(enc_p->secret.input.password_buffer, 0, sizeof(enc_p->secret.input.password_buffer));
    memset(enc_p->secret.input.check_buffer   , 0, sizeof(enc_p->secret.input.check_buffer)   );
    int pw_size = SSC_Terminal_getPasswordChecked(
     enc_p->secret.input.password_buffer,
     enc_p->secret.input.check_buffer,
     PPQ_COMMON_PASSWORD_PROMPT,
     PPQ_COMMON_REENTRY_PROMPT,
     1,
     PPQ_COMMON_MAX_PASSWORD_BYTES,
     (PPQ_COMMON_MAX_PASSWORD_BYTES + 1));
    enc_p->secret.input.password_size = pw_size;
    SSC_Terminal_end();
  }
  {
    PPQ_CSPRNG* const csprng_p = &enc_p->secret.input.csprng;
    PPQ_CSPRNG_init(csprng_p);
    if (enc_p->secret.input.supplement_entropy) {
      SSC_Terminal_init();
      memset(enc_p->secret.input.check_buffer, 0, sizeof(enc_p->secret.input.check_buffer));
      int pw_size = SSC_Terminal_getPassword(
       enc_p->secret.input.check_buffer,
       PPQ_COMMON_ENTROPY_PROMPT,
       1,
       PPQ_COMMON_MAX_PASSWORD_BYTES,
       (PPQ_COMMON_MAX_PASSWORD_BYTES + 1));
      SSC_Terminal_end();
      PPQ_Skein512_hashNative(
       &enc_p->secret.ubi512,
       enc_p->secret.hash_out,
       enc_p->secret.input.check_buffer,
       pw_size);
      SSC_secureZero(enc_p->secret.input.check_buffer, sizeof(enc_p->secret.input.check_buffer));
      PPQ_CSPRNG_reseed(csprng_p, enc_p->secret.hash_out);
      SSC_secureZero(enc_p->secret.hash_out, sizeof(enc_p->secret.hash_out));
    }
  }
  PPQ_DragonflyV1_encrypt(enc_p, &ctx->input_map, &ctx->output_map, ctx->output_filename);
  SSC_secureZero(enc_p, sizeof(*enc_p));
  DEALLOC_M_(enc_p);
}

void threecrypt_decrypt_ (Threecrypt * ctx) {
  ctx->input_map.file = SSC_FilePath_openOrDie(ctx->input_filename, true);
  SSC_MemMap_mapOrDie(&ctx->input_map, true);
  int const method = determine_crypto_method_(&ctx->input_map);
  switch (method) {
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
  case THREECRYPT_METHOD_DRAGONFLY_V1: {
    ctx->output_map.file = SSC_FilePath_createOrDie(ctx->output_filename);
    Decrypt_t dfly_dcrypt;
    PPQ_DragonflyV1Decrypt_init(&dfly_dcrypt);
    memset(dfly_dcrypt.password, 0, sizeof(dfly_dcrypt.password));
    {
      SSC_Terminal_init();
      dfly_dcrypt.password_size = SSC_Terminal_getPassword(
       dfly_dcrypt.password,
       PPQ_COMMON_PASSWORD_PROMPT,
       1,
       PPQ_COMMON_MAX_PASSWORD_BYTES,
       (PPQ_COMMON_MAX_PASSWORD_BYTES + 1));
      SSC_Terminal_end();
    }
    PPQ_DragonflyV1_decrypt(
     &dfly_dcrypt,
     &ctx->input_map,
     &ctx->output_map,
     ctx->output_filename);
    SSC_secureZero(&dfly_dcrypt, sizeof(dfly_dcrypt));
  } break; /* THREECRYPT_METHOD_DRAGONFLY_V1 */
#else
 #error "Only supported method!"
#endif
  case THREECRYPT_METHOD_NONE:
    SSC_errx("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s", ctx->input_filename, Help_Suggestion);
    break;
  default:
    SSC_errx("Error: Invalid decryption method %d\n", method);
    break;
  } /* switch( method ) */
}
void threecrypt_dump_ (Threecrypt * ctx) {
  ctx->input_map.file = SSC_FilePath_openOrDie(ctx->input_filename, true);
  SSC_MemMap_mapOrDie(&ctx->input_map, true);
  Threecrypt_Method_t method = determine_crypto_method_(&ctx->input_map);
  switch (method) {
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
  case THREECRYPT_METHOD_DRAGONFLY_V1:
    PPQ_DragonflyV1_dumpHeader(&ctx->input_map, ctx->input_filename);
    break;
#endif
  case THREECRYPT_METHOD_NONE:
    SSC_errx("Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s", ctx->input_filename, Help_Suggestion);
    break;
  default:
    SSC_errx("Error: Invalid decryption method %d\n", method);
    break;
  } /* switch( method ) */
}

#if THREECRYPT_USE_ENTROPY
 #define ENTROPY_HELP_LINE_ "-E, --entropy           Provides entropy to the RNG from stdin.\n"
#else
 #define ENTROPY_HELP_LINE_ /* Nil. */
#endif

void print_help(const char* topic) {
  if (topic == NULL) {
    printf(
      ".------.\n"
      "|3crypt|\n"
      "'------'\n"
      "-h, --help=<topic>      Print help output. If <topic> provided, print specific help. Try --help=help.\n"
      "-e, --encrypt           Symmetrically encrypt a file.\n"
      "-d, --decrypt           Symmetrically decrypt a file.\n"
      "-D, --dump              Dump information on an encrypted file.\n"
      "-i, --input=<filepath>  Specifies an input filepath.\n"
      "-o, --output=<filepath> Specifies an output filepath.\n"
      ENTROPY_HELP_LINE_
    );
    return;
  }
  /* Begin defining the help strings. */
  static const char* help_help = "Switch: -h, --help=<topic>\n"
                                 "Gives tips and usage details for different command-line switches.\n"
                                 "Topics: encrypt, decrypt, dump"
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
                                 ", dfly_v1"
#endif
                                 "\n"; /* ! help_help */
  static const char* encrypt_help = "Switch: -e, --encrypt\n"
                                    "Symmetrically encrypt a file.\n"
                                    "-i, --input=<filepath>   Specifies the file to be encrypted.\n"
                                    "-o, --output=<filepath>  Specifies where to output the encrypted file.\n"
#if THREECRYPT_USE_ENTROPY
                                    "-E, --entropy            Specifies to supplement RNG entropy from stdin.\n"
                                    "                         Only applicable if RNG is used.\n"
#endif
#if THREECRYPT_USE_KEYFILES
                                    "-K, --keyfile=<filepath> Specifies where to place the generated keyfile.\n"
                                    "                         Only applicable if using keyfiles and not passwords.\n"
#endif
                                    "Method-Specific-Options:\n"
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
                                    "Dragonfly_V1: Memory-Hard password-SSCd symmetric encryption.\n"
                                    "Use --help=dfly_v1 for more info.\n"
#endif
                                    ; /* ! encrypt_help */
  static const char* decrypt_help = "Switch: -d, --decrypt\n"
                                    "Symmetrically decrypt a file.\n"
                                    "-i, --input=<filepath>  Specifies the file to be decrypted.\n"
                                    "-o, --output=<filepath> Specifies where to output the decrypted file.\n"
#if THREECRYPT_USE_KEYFILES
                                    "-K, --keyfile=<filepath> Specifies the keyfile to decrypt with.\n"
                                    "                         Only applicable if using keyfiles and not passwords.\n"
#endif
                                    ; /* ! decrypt_help */
  static const char* dump_help = "Switch: -D, --dump\n"
                                 "Dump the header of an encrypted file.\n"
                                 "-i, --input=<filepath> Specifies the encrypted file to dump.\n";
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
 #if (THREECRYPT_METHOD_DEFAULT == THREECRYPT_METHOD_DRAGONFLY_V1)
  #define METHOD_ "Method: Dragonfly_V1, the default method.\n"
 #else
  #define METHOD_ "Method: Dragonfly_V1, alternative method.\n"
 #endif
  static const char* dfly_v1_help = METHOD_
                                    "Memory-hard password-SSCd file encryption.\n"
                                    "--min-memory=<num_bytes>[K|M|G] Minimum amount of memory to consume\n"
                                    "                                during key-derivation.\n"
                                    "--max-memory=<num_bytes>[K|M|G] Maximum amount of memory to consume\n"
                                    "                                during key-derivation.\n"
                                    "--use-memory=<num_bytes>[K|M|G] Minimum and maximum memory to consume\n"
                                    "                                during key-derivation.\n"
                                    "  The more memory used for key derivation, the slower it will be\n"
                                    "  to brute-force your password.\n"
                                    "  Memory values are rounded down to the nearest power of 2.\n"
                                    "--iterations=<num> The number of times to iterate the memory-hard function\n"
                                    "                   during key-derivation.\n"
                                    "--pad-by=<num_bytes>[K|M|G] A number of bytes to pad the encrypted file,\n"
                                    "                            to obfuscate its size.\n"
                                    "--pad-to=<num_bytes>[K|M|G] The target number of bytes you want your encrypted\n"
                                    "                            file to be; will fail if not large enough.\n"
                                    "--pad-as-if=<num_bytes>[K|M|G] Add padding such that the encrypted file is the\n"
                                    "                               same size as an unpadded encrypted file.\n"
                                    "--use-phi Enable the optional phi function.\n"
                                    "  WARNING: The phi function hardens the key-derivation function against\n"
                                    "  parallel adversaries, greatly increasing the work necessary to brute-force\n"
                                    "  your password, but introduces the potential for cache-timing attacks.\n"
                                    "  Do NOT use this feature unless you understand the security implications!\n"; /* ! dfly_v1_help */
#endif
  /* End defining the help strings. */

  size_t len = strlen(topic);
  switch (len) {
    case (sizeof("help") - 1):
    /* Implicitly:
    case (sizeof("dump") - 1): */
      if (strcmp(topic, "help") == 0)
        printf(help_help);
      else if (strcmp(topic, "dump") == 0)
        printf(dump_help);
      else
        fprintf(stderr, "Error: Invalid help topic '%s'.\n", topic);
      break;
    case (sizeof("encrypt") - 1):
    /* Implicitly:
    case (sizeof("decrypt") - 1): */
      if (strcmp(topic, "encrypt") == 0)
        printf(encrypt_help);
      else if (strcmp(topic, "decrypt") == 0)
        printf(decrypt_help);
#if THREECRYPT_METHOD_DRAGONFLY_V1_ISDEF
    /* Implicitly:
    case (sizeof("dfly_v1") - 1): */
      else if (strcmp(topic, "dfly_v1") == 0)
        printf(dfly_v1_help);
#endif
      else
        fprintf(stderr, "Error: Invalid help topic '%s'.\n", topic);
      break; /* ! case (sizeof("encrypt") - 1): */
  } /* ! switch (len) */
} /* ! print_help */
