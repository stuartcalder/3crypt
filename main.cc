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

#ifdef __OpenBSD__
#	include <unistd.h>	// Include unistd.h for unveil().
#endif

enum class Mode_e {
	None,
	Symmetric_Encrypt,
	Symmetric_Decrypt,
	Dump_Fileheader,
	Terminating_Enum
};

static constexpr auto const & Help_String = "Usage: 3crypt Mode [Switches...]\n\n"
					    "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n\n"
					    "Modes:\n"
					    "-e, --encrypt  Symmetric encryption mode; encrypt a file using a passphrase.\n"
					    "-d, --decrypt  Symmetric decryption mode; decrypt a file using a passphrase.\n"
					    "--dump-header  Dump information on a 3crypt encrypted file; must specify an input-file.\n\n"
					    "Switches:\n"
					    "-i, --input-file  Input file ; Must be specified for symmetric encryption and decryption modes.\n"
					    "-o, --output-file Output file; For symmetric encryption and decryption modes. Optional for encryption.\n"
					    "--iter-count      Iteration Count (Default: 1,000,000); Higher takes more time. May only be specified for encryption.\n"
					    "--concat-count    Concatenation Count (Default: 1,000,000); Higher takes more time. May only be specified for encryption.\n";
static constexpr auto const & Help_Suggestion = "( Use 3crypt --help for more information )\n";
#ifdef __SSC_CBC_V2__
using Default_Input_t = typename ssc::cbc_v2::Encrypt_Input;
#else
#	error "CBC_V2 the only currently supported decrypt method."
#endif
using Crypto_Method_e = typename ssc::Crypto_Method_e;
using Arg_Map_t = typename ssc::Arg_Mapping::Arg_Map_t;
using namespace ssc::ints;

/*
 * Arg_Map_t process_mode_args(Arg_Map_t && in_map, Mode_e & mode)
 *  Inputs:     Arg_Map_t universal reference, and a Mode enum reference.
 *  Outputs:    returns unused argument pairs, writes detected mode to the mode reference
 */
static Arg_Map_t
process_mode_args	(Arg_Map_t && in_map, Mode_e & mode) {

	Arg_Map_t extraneous_args;
	static constexpr auto const & Mode_Already_Set = "Error: Program mode already set.\n"
							 "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";

	for (int i = 1; i < in_map.size(); ++i) {
		if (in_map[ i ].first == "-e" || in_map[ i ].first == "--encrypt") {
			if (mode != Mode_e::None) {
				std::fputs( Mode_Already_Set, stderr );
				std::fputs( Help_Suggestion , stderr );
				std::exit( EXIT_FAILURE );
			}
			mode = Mode_e::Symmetric_Encrypt;
		} else if (in_map[ i ].first == "-d" || in_map[ i ].first == "--decrypt") {
			if (mode != Mode_e::None) {
				std::fputs( Mode_Already_Set, stderr );
				std::fputs( Help_Suggestion , stderr );
				std::exit( EXIT_FAILURE );
			}
			mode = Mode_e::Symmetric_Decrypt;
		} else if (in_map[ i ].first == "--dump-header") {
			if (mode != Mode_e::None) {
				std::fputs( Mode_Already_Set, stderr );
				std::fputs( Help_Suggestion , stderr );
				std::exit( EXIT_FAILURE );
			}
			mode = Mode_e::Dump_Fileheader;
		} else if (in_map[ i ].first == "-h" || in_map[ i ].first == "--help") {
			std::puts( Help_String );
			std::exit( EXIT_SUCCESS );
		} else if (in_map[ i ].first.empty() && !(in_map[ i ].second.empty())) {
			std::fprintf( stderr, "Error: floating arguments ( %s ) not allowed.\n", in_map[ i ].second.c_str() );
			std::fputs( Help_Suggestion, stderr );
			std::exit( EXIT_FAILURE );
		} else
			extraneous_args.push_back( std::move( in_map[ i ] ) );
	}
	return extraneous_args;
}/* process_mode_args */

/*
 * Arg_Map_t process_encrypt_arguments(Arg_Map_t && opt_arg_pairs,
 *                                     std::string & input_filename,
 *                                     std::string & output_filename)
 *  *Inputs:     Arg_Map_t universal reference, std::string reference for the input
 *               file's name, std::string reference for the output file's name
 *  *Outputs:    input and output filenames are written, return unused argument
 *               pairs
 */
static Arg_Map_t
process_encrypt_arguments	(Arg_Map_t && opt_arg_pairs,
		                 Default_Input_t & encr_input) {
	using namespace std;

	Arg_Map_t extraneous_args;

	encr_input.input_filename.clear();
	encr_input.output_filename.clear();
	encr_input.number_iterations = 1'000'000;
	encr_input.number_concatenations = 1'000'000;

	for (auto && pair : opt_arg_pairs) {
		ssc::check_file_name_sanity( pair.second, 1 );
		// Get the input and output filenames
		if (pair.first == "-i" || pair.first == "--input-file") {
			encr_input.input_filename = pair.second;
			if (encr_input.output_filename.empty())
				encr_input.output_filename = encr_input.input_filename + ".3c";
		} else if (pair.first == "-o" || pair.first == "--output-file") {
			encr_input.output_filename = pair.second;
		} else if (pair.first == "--iter-count") {	// Absolutely optional arguments
			static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
			std::string count = move( pair.second );
			if (count.size() > Max_Count_Chars) {
				fprintf( stderr, "Error: The specified iteration count (%s) too large.\n", count.c_str() );
				fputs( Help_Suggestion, stderr );
				exit( EXIT_FAILURE );
			}
			if (ssc::enforce_integer( count )) {
				auto const num_iter = static_cast<u32_t>(atoi( count.c_str() ));
				if (num_iter == 0) {
					fputs( "Error: number iterations specified is zero.\n", stderr );
					exit( EXIT_FAILURE );
				}
				encr_input.number_iterations = num_iter;
			}
		} else if (pair.first == "--concat-count") {
			static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
			string count = move( pair.second );
			if (count.size() > Max_Count_Chars) {
				fprintf( stderr, "Error: The specified concatenation count (%s) too large.\n", count.c_str() );
				fputs( Help_Suggestion, stderr );
				exit( EXIT_FAILURE );
			}
			if (ssc::enforce_integer( count )) {
				auto const num_concat = static_cast<u32_t>(atoi( count.c_str() ));
				if (num_concat == 0) {
					fputs( "Error: number concatenations specified is zero.\n", stderr );
					exit( EXIT_FAILURE );
				}
				encr_input.number_concatenations = num_concat;
			}
		} else
			extraneous_args.push_back( move( pair ) );
	}/*for (auto && pair : opt_arg_pairs)*/
	if (encr_input.input_filename.empty()) {
		fputs( "Error: The input filename was not specified.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	if (encr_input.output_filename.empty()) {
		fputs( "Error: the output filename was not specified.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	return extraneous_args;
}/* process_encrypt_arguments */

static Arg_Map_t
process_decrypt_arguments	(Arg_Map_t && opt_arg_pairs,
                                 std::string & input_filename,
                                 std::string & output_filename) {
	using namespace std;

	Arg_Map_t extraneous_args;

	input_filename.clear();
	output_filename.clear();

	for (auto && pair : opt_arg_pairs) {
		ssc::check_file_name_sanity( pair.second, 1 );
		if (pair.first == "-i" || pair.first == "--input-file") {
			input_filename = pair.second;
			if (output_filename.empty() &&
			    input_filename.size() >= 4 &&
			    input_filename.substr( input_filename.size() - 3 ) == ".3c")
			{
				output_filename = input_filename.substr( 0, input_filename.size() - 3 );
			}
		} else if (pair.first == "-o" || pair.first == "--output-file")
			output_filename = pair.second;
		else
			extraneous_args.push_back( std::move( pair ) );
	}
	if (input_filename.empty()) {
		fputs( "Error: The input filename was not specified.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	if (output_filename.empty()) {
		fputs( "Error: The output filename was not specified.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	return extraneous_args;
}/* process_decrypt_arguments */

static Arg_Map_t
process_dump_header_arguments (Arg_Map_t &&opt_arg_pairs, std::string &filename) {
	using namespace std;

	Arg_Map_t extraneous_args;

	for (auto && pair : opt_arg_pairs) {
		ssc::check_file_name_sanity( pair.second, 1 );
		if (pair.first == "-i" || pair.first == "--input-file")
			filename = pair.second;
		else
			extraneous_args.push_back( move( pair ) );
	}
	if (filename.empty()) {
		fputs( "Error: Input filename not specified for file-header dump.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	return extraneous_args;
}/* process_dump_header_arguments */

static void
die_unneeded_args	(Arg_Map_t const & args) {
	std::fprintf( stderr, "Error: Unneeded or illegal options or arguments: " );
	for (auto const & pair : args)
		std::fprintf( stderr, "%s -> %s, ", pair.first.c_str(), pair.second.c_str() );
	std::fputc( '\n', stderr );
	std::fputs( Help_Suggestion, stderr );
	std::exit( EXIT_FAILURE );
}/* die_unneeded_args */

int
main	(int const argc, char const *argv[]) {

	auto mode = Mode_e::None;
	Default_Input_t input;
	ssc::Arg_Mapping args{ argc, argv };
	auto mode_specific_arguments = process_mode_args( args.consume(), mode );

	switch (mode) {
		default:
		case (Mode_e::None):
			std::fprintf( stderr, "Error: No mode selected, or invalid mode: ( %d ) \n", static_cast<int>(mode) );
			fputs( Help_Suggestion, stderr );
			std::exit( EXIT_FAILURE );
		case (Mode_e::Symmetric_Encrypt):
			{
				auto const remaining_args = process_encrypt_arguments( std::move( mode_specific_arguments ), input );
				if (!remaining_args.empty())
					die_unneeded_args( remaining_args );
			}
#ifdef __OpenBSD__
			// Allow reading and executing everything under /usr.
			if (unveil( "/usr", "rx" ) != 0) {
				std::fputs( "Error: Failed to unveil() /usr\n", stderr );
				std::exit( EXIT_FAILURE );
			}
			// Allow reading the input file.
			if (unveil( input.input_filename.c_str(), "r" ) != 0) {
				std::fputs( "Error: Failed to unveil() the input file...\n", stderr );
				std::exit( EXIT_FAILURE );
			}
			// Allow reading, writing, and creating the output file.
			if (unveil( input.output_filename.c_str(), "rwc" ) != 0) {
				std::fputs( "Error: Failed to unveil() the output file...\n", stderr );
				std::exit( EXIT_FAILURE );
			}
			// Disable further unveil() calls.
			if (unveil( nullptr, nullptr ) != 0) {
				std::fputs( "Error: Failed to finalize unveil()\n", stderr );
				std::exit( EXIT_FAILURE );
			}
#endif/*#ifdef __OpenBSD__*/
#ifdef __SSC_CBC_V2__
			ssc::cbc_v2::encrypt( input );
#else
#	error		"CBC_V2 is the only supported encryption method, but it is not currentlt enabled."
#endif
			break;
		case (Mode_e::Symmetric_Decrypt):
			{
				auto const remaining_args = process_decrypt_arguments( std::move( mode_specific_arguments ),
										       input.input_filename, input.output_filename );
				if (!remaining_args.empty())
					die_unneeded_args( remaining_args );
				ssc::enforce_file_existence( input.input_filename.c_str(), true );
				auto const method = ssc::determine_crypto_method( input.input_filename.c_str() );
#ifdef __OpenBSD__
				// Allow reading everything under /usr.
				if (unveil( "/usr", "rx" ) != 0) {
					std::fputs( "Error: Failed to unveil() /usr\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Allow reading the input file.
				if (unveil( input.input_filename.c_str(), "r" ) != 0) {
					std::fputs( "Error: Failed to unveil() the input file...\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Allow reading, writing, and creating the output file.
				if (unveil( input.output_filename.c_str(), "rwc" ) != 0) {
					std::fputs( "Error: Failed to unveil() the output file...\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Disable further unveil() calls.
				if (unveil( nullptr, nullptr ) != 0) {
					std::fputs( "Error: Failed to finalize unveil()\n", stderr );
					std::exit( EXIT_FAILURE );
				}
#endif/*#ifdef __OpenBSD__*/
				switch (method) {
					default:
						std::fprintf( stderr, "Error: Invalid decrypt method ( %d ).\n", static_cast<int>(method) );
						std::fputs( Help_Suggestion, stderr );
						std::exit( EXIT_FAILURE );
					case (Crypto_Method_e::None):
						std::fprintf( stderr, "Error: The input file `%s` does not appear to be a valid encrypted file.\n",
								input.input_filename.c_str() );
						std::fputs( Help_Suggestion, stderr );
						std::exit( EXIT_FAILURE );
#ifdef __SSC_CBC_V2__
					case (Crypto_Method_e::CBC_V2):
						ssc::cbc_v2::decrypt( input.input_filename.c_str(), input.output_filename.c_str() );
						break;
#else
#	error	"Currently, only CBC_V2 is supported, and it appears to not be present."
#endif/*#ifdef __SSC_CBC_V2__*/
				}/*switch(method)*/
			}
			break;/*case(Mode_e::Symmetric_Decrypt)*/
		case (Mode_e::Dump_Fileheader):
			{
				auto const remaining_args = process_dump_header_arguments( std::move( mode_specific_arguments ), input.input_filename );
				if (!remaining_args.empty())
					die_unneeded_args( remaining_args );
				ssc::enforce_file_existence( input.input_filename.c_str(), true );
				auto const method = ssc::determine_crypto_method( input.input_filename.c_str() );
#ifdef __OpenBSD__
				if (unveil( "/usr", "rx" ) != 0) {
					std::fputs( "Error: Failed to unveil() /usr before decrypt...\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				if (unveil( input.input_filename.c_str(), "r" ) != 0) {
					std::fputs( "Error: Failed to unveil() input file before header dump...\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				if (unveil( nullptr, nullptr ) != 0) {
					std::fputs( "Error: Failed to finalize unveil()\n", stderr );
					std::exit( EXIT_FAILURE );
				}
#endif/*#ifdef __OpenBSD__*/
				switch (method) {
					default:
					case (Crypto_Method_e::None):
						std::fprintf( stderr, "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n",
							      input.input_filename.c_str() );
						std::fputs( Help_Suggestion, stderr );
						std::exit( EXIT_FAILURE );
#ifdef __SSC_CBC_V2__
					case (Crypto_Method_e::CBC_V2):
						ssc::cbc_v2::dump_header( input.input_filename.c_str() );
						break;
#endif/*#ifdef __SSC_CBC_V2__*/
				}
			}
			break;/*case(Mode_e::Dump_Fileheader)*/
	} /*switch(mode)*/

	return EXIT_SUCCESS;
}
