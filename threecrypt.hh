#define __STDC_FORMAT_MACROS
#include <cinttypes>
#include <cstdlib>
#include <utility>

#include <ssc/general/macros.hh>
#include <ssc/general/parse_string.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/c_argument_map.hh>

#ifdef THREECRYPT_EXT_ENABLE_DRAGONFLY_V1
#	include <ssc/crypto/implementation/dragonfly_v1.hh>
#endif
#ifdef THREECRYPT_EXT_ENABLE_CBC_V2
#	include <ssc/crypto/implementation/cbc_v2_f.hh>
#endif

#include <ssc/crypto/implementation/determine_crypto_method.hh>

#if  (!defined (SSC_FEATURE_DRAGONFLY_V1) && !defined (SSC_FEATURE_CBC_V2))
#	error 'No supported crypto method detected!'
#endif
using namespace ssc::ints;

using Crypto_Method_E = typename ssc::crypto_impl::Crypto_Method_E;
enum class Mode_E {
	None,
	Symmetric_Encrypt,
	Symmetric_Decrypt,
	Dump_Fileheader
};

struct Threecrypt_Data
{
#if    defined (SSC_FEATURE_DRAGONFLY_V1)
	ssc::crypto_impl::Catena_Input input;
#elif  defined (SSC_FEATURE_CBC_V2)
	ssc::crypto_impl::SSPKDF_Input input;
#else
#	error 'No valid crypto method detected'
#endif
	ssc::OS_Map input_map;
	ssc::OS_Map output_map;
	char const *input_filename;
	char const *output_filename;
	size_t input_filename_size;
	size_t output_filename_size;
	Mode_E mode;
};

static constexpr auto &Mode_Already_Set =  "Error: Program mode already set\n"
					   "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";

static constexpr auto &Help_String = "Usage: 3crypt <Mode> [Switches...]\n"
			             "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n\n"
			             "Modes\n"
				     "-----\n"
			             "-h, --help\t\tPrint this help output.\n"
			             "-e, --encrypt\t\tSymmetric encryption mode; encrypt a file using a passphrase.\n"
			             "-d, --decrypt\t\tSymmetric decryption mode; decrypt a file using a passphrase.\n"
			             "-D, --dump\t\tDump information on a 3crypt encrypted file; must specify an input file.\n\n"
			             "Switches\n"
				     "--------\n"
			             "-i, --input  <filename>\t\tSpecifies the input file.\n"
			             "-o, --output <filename>\t\tSpecifies the output file. Only applies to encryption and decryption.\n"
			             "-E, --entropy\t\t\tProvide random input characters to increase the entropy of the pseudorandom number generator.\n\n"
#if    defined (SSC_FEATURE_DRAGONFLY_V1)
				   "Dragonfly_V1 Encryption Options\n"
				   "-------------------------------\n"
				   "--min-memory <number_bytes>[K|M|G]\tThe minimum amount of memory to consume during key-derivation. Minimum memory cost.\n"
				   "--max-memory <number_bytes>[K|M|G]\tThe maximum amount of memory to consume during key-derivation. Maximum memory cost.\n"
				   "--use-memory <number_bytes>[K|M|G]\tThe precise amount of memory to consume during key-derivation. Precise memory cost.\n"
				   "    The more memory we use for key-derivation, the harder it will be to attack your password.\n"
				   "    Setting only one of these memory parameters will set the other to the same value.\n"
				   "    Memory minimums and maximums are rounded down to the closest power of 2.\n"
				   "--iterations <number>\tThe number of times to iterate the memory-hard function during key-derivation. Time cost.\n"
				   "--pad-by <number_bytes>[K|M|G]\tThe number of padding bytes to add the to encrypted file, to obfuscate how large it is.\n"
				   "--pad-to <number_bytes>[K|M|G]\tThe target number of bytes you want your encrypted file to be; will fail if it's not big enough to hold the original with a header.\n"
				   "--use-phi\t\tWhether to enable the optional Phi-function or not.\n"
				   "    WARNING: The optional phi function hardens the key-derivation function against\n"
				   "    parallel adversaries, greatly increasing the work necessary to attack your\n"
				   "    password, but introduces the potential for cache-timing attacks...\n"
				   "    Do NOT use this feature unless you understand the security implications!"
#elif  defined (SSC_FEATURE_CBC_V2)
				   "CBC_V2 Encryption Options:\n"
			           "--iter-count              : Iteration Count for sspkdf (Default: 1,000,000)\n"
			           "                               The more sspkdf iterations, the longer it will take to guess a password.\n"
			           "--concat-count            : Concatenation Count for sspkdf (Default: 1,000,000)\n"
			           "                               The number of times to concatenate the password, salt, and index counter.\n"
			           "                               The more concatenations, the more time it will take to guess a password."
#else
#	error 'No supported crypto method detected.'
#endif
				   "\n";

static constexpr auto &Help_Suggestion = "(Use 3crypt --help for more information )\n";

void SSC_PUBLIC
threecrypt (int const argc, char const *argv[]);

#ifdef SSC_FEATURE_DRAGONFLY_V1
u8_t
dragonfly_parse_memory (SSC_RESTRICT (char const*) mem_c_str,
		        SSC_RESTRICT (char*)       temp,
			int const                  size);
u8_t

dragonfly_parse_iterations (SSC_RESTRICT (char const*) iter_c_str,
		            SSC_RESTRICT (char*)       temp,
		            int const                  size);

u64_t
dragonfly_parse_padding (SSC_RESTRICT (char const*) pad_c_str,
		         SSC_RESTRICT (char*)       temp,
			 int const                  size);
#endif

void
process_io_arguments (Threecrypt_Data     &tc_data,
		      ssc::C_Argument_Map &c_arg_map);
void
process_mode_arguments (Threecrypt_Data     &tc_data,
			ssc::C_Argument_Map &c_arg_map);
void
process_encrypt_arguments (Threecrypt_Data     &tc_data,
			   ssc::C_Argument_Map &c_argument_map);
