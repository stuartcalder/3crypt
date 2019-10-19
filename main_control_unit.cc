/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <type_traits>
#include "main_control_unit.hh"

#ifdef __OpenBSD__
#	include <unistd.h>
#endif

namespace _3crypt {
	Main_Control_Unit::Main_Control_Unit (int const arg_count, char const *arg_vect[]) {
		auto mode_specific_arguments = process_mode_arguments_( ssc::Arg_Mapping{ arg_count, arg_vect }.consume(), mode );
		switch (mode) {
			default:
			case (Mode_E::None):
				std::fprintf( stderr, "Error: No mode selected, or invalid mode: ( %d )\n", static_cast<int>(mode) );
				std::fputs( Help_Suggestion, stderr );
				std::exit( EXIT_FAILURE );
			case (Mode_E::Symmetric_Encrypt):
				{
					auto const remaining_arguments = process_encrypt_arguments_( std::move( mode_specific_arguments ), input );
					if (!remaining_arguments.empty()) {
						die_unneeded_arguments_( remaining_arguments );
					}
				}
#ifdef __OpenBSD__
				// Allow reading and executing everything under /usr.
				if (unveil( "/usr", "rx" ) != 0) {
					std::fputs( "Failed to unveil() /usr\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Allow reading the input file.
				if (unveil( input.input_filename.c_str(), "r" ) != 0) {
					std::fputs( "Failed to unveil() the input file\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Allow reading, writing, and creating the input file.
				if (unveil( input.output_filename.c_str(), "rwx" ) != 0) {
					std::fputs( "Failed to unveil() the outputr file\n", stderr );
					std::exit( EXIT_FAILURE );
				}
				// Finalize the unveil calls.
				if (unveil( nullptr, nullptr ) != 0) {
					std::fputs( "Failed to finalize unveil()\n", stderr );
					std::exit( EXIT_FAILURE );
				}
#endif/*#ifdef __OpenBSD__*/
#ifdef __SSC_CBC_V2__
				ssc::cbc_v2::encrypt( input );
#else
#	error			"CBC_V2 is the only supported crypt method."
#endif/*#ifdef __SSC_CBC_V2__*/
				break;
			case (Mode_E::Symmetric_Decrypt):
				{
					auto const remaining_arguments = process_decrypt_arguments_( std::move( mode_specific_arguments ), input.input_filename, input.output_filename );
					if (!remaining_arguments.empty())
						die_unneeded_arguments_( remaining_arguments );
#ifdef __OpenBSD__
					// Allow reading and executing everything under /usr.
					if (unveil( "/usr", "rx" ) != 0) {
						std::fputs( "Failed to unveil() /usr\n", stderr );
						std::exit( EXIT_FAILURE );
					}
					// Allow reading the input file.
					if (unveil( input.input_filename.c_str(), "r" ) != 0) {
						std::fputs( "Failed to unveil() the input file\n", stderr );
						std::exit( EXIT_FAILURE );
					}
					// Allow reading, writing, modifying the output file.
					if (unveil( input.output_filename.c_str(), "rwx" ) != 0) {
						std::fputs( "Failed to unveil() the output file\n", stderr );
						std::exit( EXIT_FAILURE );
					}
					// Finalize the unveil calls.
					if (unveil( nullptr, nullptr ) != 0) {
						std::fputs( "Failed to finalize unveil()\n", stderr );
						std::exit( EXIT_FAILURE );
					}
#endif/*#ifdef __OpenBSD__*/
					ssc::enforce_file_existence( input.input_filename.c_str(), true );
					auto const crypt_method = ssc::determine_crypto_method( input.input_filename.c_str() );
					switch (crypt_method) {
						default:
							std::fprintf( stderr, "Error: Invalid decrypt method ( %d ).\n", static_cast<int>(crypt_method) );
							std::fputs( Help_Suggestion, stderr );
							std::exit( EXIT_FAILURE );
						case (Crypto_Method_e::None):
							std::fprintf( stderr, "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n", input.input_filename.c_str() );
							std::fputs( Help_Suggestion, stderr );
							std::exit( EXIT_FAILURE );
#ifdef __SSC_CBC_V2__
						case (Crypto_Method_e::CBC_V2):
							ssc::cbc_v2::decrypt( input.input_filename.c_str(), input.output_filename.c_str() );
							break;
#endif
					}/*switch (method)*/
				}
				break;
			case (Mode_E::Dump_Fileheader):
				{
					auto const remaining_arguments = process_dump_header_arguments_( std::move( mode_specific_arguments ), input.input_filename );
					if (!remaining_arguments.empty())
						die_unneeded_arguments_( remaining_arguments );
					ssc::enforce_file_existence( input.input_filename.c_str(), true );
					auto const method = ssc::determine_crypto_method( input.input_filename.c_str() );
					switch (method) {
						default:
						case (Crypto_Method_e::None):
							std::fprintf( stderr, "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n", input.input_filename.c_str() );
							std::fputs( Help_Suggestion, stderr );
							std::exit( EXIT_FAILURE );
#ifdef __SSC_CBC_V2__
						case (Crypto_Method_e::CBC_V2):
							ssc::cbc_v2::dump_header( input.input_filename.c_str() );
							break;
#endif
					}/*switch (method)*/
				}
				break;
		}/*switch (mode)*/
	}/*Main_Control_Unit{int const,char const *[]}*/
/////////////////////////////////////////////////////////////End of the Main Control Unit Constructor Code/////////////////////////////////////////////////////////////////////////////////////////////
	Arg_Map_t
	Main_Control_Unit::process_mode_arguments_ (Arg_Map_t &&in_map, Mode_E &mode) {
		using std::fprintf, std::fputs, std::exit;
		Arg_Map_t extraneous_arguments;
		static constexpr auto const &Mode_Already_Set = "Error: Program mode already set\n"
								"(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";
		for (size_t i = 1; i < in_map.size(); ++i) {
			if (in_map[ i ].first == "-e" || in_map[ i ].first == "--encrypt") {
				if (mode != Mode_E::None) {
					fputs( Mode_Already_Set, stderr );
					fputs( Help_Suggestion, stderr );
					exit( EXIT_FAILURE );
				}
				mode = Mode_E::Symmetric_Encrypt;
			} else if (in_map[ i ].first == "-d" || in_map[ i ].first == "--decrypt") {
				if (mode != Mode_E::None) {
					fputs( Mode_Already_Set, stderr );
					fputs( Help_Suggestion, stderr );
					exit( EXIT_FAILURE );
				}
				mode = Mode_E::Symmetric_Decrypt;
			} else if (in_map[ i ].first == "--dump-header") {
				if (mode != Mode_E::None) {
					fputs( Mode_Already_Set, stderr );
					fputs( Help_Suggestion, stderr );
					exit( EXIT_FAILURE );
				}
				mode = Mode_E::Dump_Fileheader;
			} else if (in_map[ i ].first == "-h" || in_map[ i ].first == "--help") {
				fputs( Help_String, stdout );
				exit( EXIT_SUCCESS );
			} else if (in_map[ i ].first.empty() && !(in_map[ i ].second.empty())) {
				fprintf( stderr, "Error: Floating arguments ( %s ) not allowed\n", in_map[ i ].second.c_str() );
				fputs( Help_Suggestion, stderr );
				exit( EXIT_FAILURE );
			} else {
				extraneous_arguments.push_back( std::move( in_map[ i ] ) );
			}
		}
		return extraneous_arguments;
	}/*process_mode_arguments_(Arg_Map_t&&,Mode_E&)*/

	Arg_Map_t
	Main_Control_Unit::process_encrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, Default_Input_t &encr_input) {
		Arg_Map_t extraneous_arguments;

#ifdef __SSC_CBC_V2__
		// Check that `encr_input` describes a struct that takes input, output filenames, and number iterations and concatenations (u32_t each).
		static_assert (std::is_same<Default_Input_t, ssc::cbc_v2::Encrypt_Input>::value);
#else
#	error	"Only CBC_V2 is supported now."
#endif
		encr_input.input_filename.clear();
		encr_input.output_filename.clear();
		encr_input.number_iterations     = 1'000'000;
		encr_input.number_concatenations = 1'000'000;

		for (auto &&pair : opt_arg_pairs) {
			ssc::check_file_name_sanity( pair.second, 1 );
			// Get the input and output filenames.
			if (pair.first == "-i" || pair.first == "--input-file") {
				encr_input.input_filename = pair.second;
				if (encr_input.output_filename.empty()) 
					encr_input.output_filename = encr_input.input_filename + ".3c";
			} else if (pair.first == "-o" || pair.first == "--output-file" ) {
				encr_input.output_filename = pair.second;
			} else if (pair.first == "--iter-count") {
				static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
				std::string count = std::move( pair.second );
				if (count.size() > Max_Count_Chars) {
					std::fprintf( stderr, "Error: the specified iteration count (%s) is too large.\n", count.c_str() );
					std::fputs( Help_Suggestion, stderr );
					std::exit( EXIT_FAILURE );
				}
				if (ssc::enforce_integer( count )) {
					auto const num_iter = static_cast<u32_t>(atoi( count.c_str() ));
					if (num_iter == 0) {
						std::fputs( "Error: Number iterations specified is zero.\n", stderr );
						std::exit( EXIT_FAILURE );
					}
					encr_input.number_iterations = num_iter;
				}
			} else if (pair.first == "--concat-count") {
				static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
				std::string count = std::move( pair.second );
				if (count.size() > Max_Count_Chars) {
					std::fprintf( stderr, "Error: The specified concatenation count (%s) is too large.\n", count.c_str() );
					std::fputs( Help_Suggestion, stderr );
					std::exit( EXIT_FAILURE );
				}
				if (ssc::enforce_integer( count )) {
					auto const num_concat = static_cast<u32_t>(atoi( count.c_str() ));
					if (num_concat == 0) {
						std::fputs( "Error: Number concatenations specified is zero.\n", stderr );
						std::exit( EXIT_FAILURE );
					}
					encr_input.number_concatenations = num_concat;
				}
			} else {
				extraneous_arguments.push_back( std::move( pair ) );
			}
		}/*for(auto&&:opt_arg_pairs)*/
		return extraneous_arguments;
	}/*process_encrypt_arguments_(Arg_Map_t&&,Default_Input_t&)*/

	Arg_Map_t
	Main_Control_Unit::process_decrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &input_filename, std::string &output_filename) {
		using namespace std;
		Arg_Map_t extraneous_arguments;

		input_filename.clear();
		output_filename.clear();

		for (auto &&pair : opt_arg_pairs) {
			ssc::check_file_name_sanity( pair.second, 1 );
			if (pair.first == "-i" || pair.first == "--input-file") {
				input_filename = pair.second;
				if (output_filename.empty() && (input_filename.size() >= 4) && (input_filename.substr( input_filename.size() - 3 ) == ".3c")) {
					output_filename = input_filename.substr( 0, input_filename.size() - 3 );
				}
			} else if (pair.first == "-o" || pair.first == "--output-file") {
				output_filename = pair.second;
			} else {
				extraneous_arguments.push_back( std::move( pair ) );
			}
		}
		if (input_filename.empty()) {
			fputs( "Error: the input filename was not specified (zero length filename disallowed)\n", stderr );
			fputs( Help_Suggestion, stderr );
			exit( EXIT_FAILURE );
		}
		if (output_filename.empty()) {
			fputs( "Error: the output filename was not specified (zero length filename disallowed)\n", stderr );
			fputs( Help_Suggestion, stderr );
			exit( EXIT_FAILURE );
		}
		return extraneous_arguments;
	}/*process_decrypt_arguments_(Arg_Mapt_t&&,std::string&,std::string&)*/

	Arg_Map_t
	Main_Control_Unit::process_dump_header_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &filename) {
		using namespace std;

		Arg_Map_t extraneous_arguments;

		for (auto &&pair : opt_arg_pairs) {
			ssc::check_file_name_sanity( pair.second, 1 );
			if (pair.first == "-i" || pair.second == "--input-file")
				filename = pair.second;
			else
				extraneous_arguments.push_back( move( pair ) );
		}
		if (filename.empty()) {
			fputs( "Error: Input filename not specified for file-header dump.\n", stderr );
			fputs( Help_Suggestion, stderr );
			exit( EXIT_FAILURE );
		}
		return extraneous_arguments;
	}/*process_dump_header_arguments_(Arg_Map_t&&,std::string&)*/

	void
	Main_Control_Unit::die_unneeded_arguments_ (Arg_Map_t const &args) {
		using namespace std;

		fprintf( stderr, "Error: Unneeded or illegal options or arguments: " );
		for (auto const &pair : args)
			fprintf( stderr, "%s -> %s, ", pair.first.c_str(), pair.second.c_str() );
		fputc( '\n', stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}/*die_unneeded_arguments_(Arg_Map_t const &)*/
}/*namespace _3crypt*/
