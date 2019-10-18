/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <cstdlib>
#include <string>
#include <utility>

#include <ssc/general/parse_string.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/arg_mapping.hh>
#include <ssc/crypto/implementation/cbc_v2.hh>
#include <ssc/crypto/implementation/determine_crypto_method.hh>

namespace _3crypt {

	using Crypto_Method_e = typename ssc::Crypto_Method_e;
	using Arg_Map_t       = typename ssc::Arg_Mapping::Arg_Map_t;
	using namespace ssc::ints;

	class Main_Control_Unit {
		public:
			enum class Mode_E {
				None,
				Symmetric_Encrypt,
				Symmetric_Decrypt,
				Dump_Fileheader
			};
			static constexpr auto const &Help_String = "Usage: 3crypt Mode [Switches...]\n\n"
								   "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n\n"
								   "Modes:\n"
								   "-e, --encrypt Symmetric encryption mode; encrypt a file using a passphrase.\n"
								   "-d, --decrypt Symmetric decryption mode; decrypt a file using a passphrase.\n"
								   "--dump-header Dump information on a 3crypt encrypted file; must specify an input-file.\n\n"
								   "Switches:\n"
								   "-i, --input-file  Input file ; must be specified for symmetric encryption and decryption modes.\n"
								   "-o, --output-file Output file; for symmetric encryption and decryption modes. Optional for encryption.\n"
								   "--iter-count      Iteration Count for sspkdf (Default: 1,000,000)\n"
								   "                          The more sspkdf iterations, the longer it will take to guess\n"
								   "                          a password (linearly).\n"
								   "--concat-count    Concatenation Count for sspkdf (Default: 1,000,000)\n"
								   "                          The number of times to concatenation the password, salt, and index counter.\n"
								   "                          The more concatenations, the more time it will take to guess a password.\n";
			static constexpr auto const &Help_Suggestion = "( Use 3crypt --help for more information )\n";
#ifdef __SSC_CBC_V2__
			using Default_Input_t = typename ssc::cbc_v2::Encrypt_Input;
#else
#	error		"CBC_V2 is (currently) the only supported decrypt method."
#endif

			// Disable unwanted constructors.
			Main_Control_Unit (void)			= delete;
			Main_Control_Unit (Main_Control_Unit const &)	= delete;
			Main_Control_Unit (Main_Control_Unit &&)	= delete;
			// Enable this one constructor.
			Main_Control_Unit (int const, char const * []);
		private:
			/* Private Data */
			Mode_E             mode = Mode_E::None;
			Default_Input_t   input;
			/* Private Functions */
			static Arg_Map_t
			process_mode_arguments_ (Arg_Map_t &&in_map, Mode_E &mode);

			static Arg_Map_t
			process_encrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, Default_Input_t &encr_input);

			static Arg_Map_t
			process_decrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &input_filename, std::string &output_filename);

			static Arg_Map_t
			process_dump_header_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &filename);

			static void
			die_unneeded_arguments_ (Arg_Map_t const &args);
	};
}/*namespace _3crypt*/
