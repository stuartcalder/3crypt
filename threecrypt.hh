#include <cstdlib>
#include <string>
#include <utility>

#include <ssc/general/macros.hh>
#include <ssc/general/parse_string.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/arg_mapping.hh>

#ifdef __3CRYPT_ENABLE_CBC_V2
#	include <ssc/crypto/implementation/cbc_v2_f.hh>
#endif
#ifdef __3CRYPT_ENABLE_CTR_V1
#	include <ssc/crypto/implementation/ctr_v1.hh>
#endif

#include <ssc/crypto/implementation/determine_crypto_method.hh>

#if   (!defined (__SSC_CTR_V1__) && !defined (__SSC_CBC_V2__))
#	error 'CTR_V1 or CBC_V2 must be enabled here.'
#endif
using namespace ssc::ints;

using Crypto_Method_E = typename ssc::crypto_impl::Crypto_Method_E;
using Arg_Map_t       = typename ssc::Arg_Mapping::Arg_Map_t;
enum class Mode_E {
	None,
	Symmetric_Encrypt,
	Symmetric_Decrypt,
	Dump_Fileheader
};
_CTIME_CONST (auto&) Help_String = "Usage: 3crypt <Mode> [Switches...]\n"
			           "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n"
			           "Modes:\n"
			           "-h, --help        : Print this help output.\n"
			           "-e, --encrypt     : Symmetric encryption mode; encrypt a file using a passphrase.\n"
			           "-d, --decrypt     : Symmetric decryption mode; decrypt a file using a passphrase.\n"
			           "-D, --dump        : Dump information on a 3crypt encrypted file; must specify an input file.\n"
			           "Switches:\n"
			           "-i, --input   <filename>  : Specifies the input file.\n"
			           "-o, --output  <filename>  : Specifies the output file. Only applies to encryption and decryption.\n"
			           "-E, --entropy             : Provide random input characters to increase the entropy of the pseudorandom number generator.\n"
#if    defined (__SSC_CTR_V1__)
				   /*TODO*/
#elif  defined (__SSC_CBC_V2__)
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

_CTIME_CONST (auto&) Help_Suggestion = "(Use 3crypt --help for more information )\n";

void _PUBLIC threecrypt (int const argc, char const *argv[]);
