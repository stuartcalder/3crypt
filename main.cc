#include "3crypt.hh"
#ifndef _WIN64
#	include "cbc_v1.hh"
#endif
#include "cbc_v2.hh"
#include "determine_decrypt_method.hh"
#include "input_abstraction.hh"

#include <cstdlib>
#include <string>
#include <utility>

#include <ssc/general/parse_string.hh>
#include <ssc/general/integers.hh>

enum class Mode_e {
	None,
	Symmetric_Encrypt,
	Symmetric_Decrypt,
	Dump_Fileheader,
	Terminating_Enum
};

using Arg_Map_t = typename ssc::Arg_Mapping::Arg_Map_t;
using threecrypt::Help_String, threecrypt::Help_Suggestion;
using namespace ssc::ints;

/*
 * Arg_Map_t process_mode_args(Arg_Map_t && in_map, Mode_e & mode)
 *  Inputs:     Arg_Map_t universal reference, and a Mode enum reference.
 *  Outputs:    returns unused argument pairs, writes detected mode to the mode reference
 */
static Arg_Map_t
process_mode_args	(Arg_Map_t && in_map, Mode_e & mode) {
	Arg_Map_t extraneous_args;

	for (int i = 1; i < in_map.size(); ++i) {
		if (in_map[ i ].first == "-e" || in_map[ i ].first == "--encrypt") {
			if (mode != Mode_e::None) {
				std::fputs( "Error: Program mode already set.\n"
					    "(Only one mode switch (e.g -e or -d) is allowed per invocation of 3crypt.\n", stderr );
				std::fputs( Help_Suggestion, stderr );
				std::exit( EXIT_FAILURE );
			}
			mode = Mode_e::Symmetric_Encrypt;
		} else if (in_map[ i ].first == "-d" || in_map[ i ].first == "--decrypt") {
			if (mode != Mode_e::None) {
				std::fputs( "Error: Program mode already set.\n"
					    "(Only one mode switch( e.g. -e or -d) is allowed per invocation of 3crypt.\n", stderr );
				std::fputs( Help_Suggestion, stderr );
				std::exit( EXIT_FAILURE );
			}
			mode = Mode_e::Symmetric_Decrypt;
		} else if (in_map[ i ].first == "--dump-header") {
			if (mode != Mode_e::None) {
				std::fputs( "Error: Program mode already set.\n"
					    "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n", stderr );
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
		} else {
			extraneous_args.push_back( std::move( in_map[ i ] ) );
		}
	}
	return extraneous_args;
}

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
                                 threecrypt::Input_Abstraction & input_abstr) {
	using namespace std;

	Arg_Map_t extraneous_args;

	input_abstr.number_iterations     = 1'000'000;
	input_abstr.number_concatenations = 1'000'000;
	input_abstr.input_filename.clear();
	input_abstr.output_filename.clear();

	for (auto && pair : opt_arg_pairs) {
		ssc::check_file_name_sanity( pair.second, 1 );
		// Get the input and output filenames
		if (pair.first == "-i" || pair.first == "--input-file") {
			input_abstr.input_filename = pair.second;
			if (input_abstr.output_filename.empty())
				input_abstr.output_filename = input_abstr.input_filename + ".3c";
		} else if (pair.first == "-o" || pair.first == "--output-file") {
			input_abstr.output_filename = pair.second;
		} else if (pair.first == "--iter-count") {	// Absolutely optional arguments
			static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
			string count = move( pair.second );
			if (count.size() > Max_Count_Chars) {
				fprintf( stderr, "Error: The specified iteration count (%s) too large.\n", count.c_str() );
				fputs( Help_Suggestion, stderr );
				exit( EXIT_FAILURE );
			}
			if (ssc::enforce_integer( count ))
				input_abstr.number_iterations = static_cast<u32_t>(atoi( count.c_str() ));
		} else if (pair.first == "--concat-count") {
			static constexpr decltype(pair.second.size()) const Max_Count_Chars = 10;
			string count = move( pair.second );
			if (count.size() > Max_Count_Chars) {
				fprintf( stderr, "Error: The specified concatenation count (%s) too large.\n", count.c_str() );
				fputs( Help_Suggestion, stderr );
				exit( EXIT_FAILURE );
			}
			if (ssc::enforce_integer( count ))
				input_abstr.number_concatenations = static_cast<u32_t>(atoi( count.c_str() ));
		} else
			extraneous_args.push_back( move( pair ) );
	}
	if (input_abstr.input_filename.empty()) {
		fputs( "Error: The input filename was not specified.\n", stderr );
		fputs( Help_Suggestion, stderr );
		exit( EXIT_FAILURE );
	}
	if (input_abstr.output_filename.empty()) {
		fputs( "Error: The output filename was not specified.\n", stderr );
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
			    input_filename.size() >= 3 &&
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
process_dump_header_arguments	(Arg_Map_t && opt_arg_pairs,
                                 threecrypt::Input_Abstraction & input_abstr) {
	using namespace std;

	Arg_Map_t extraneous_args;

	input_abstr.input_filename.clear();

	for (auto && pair : opt_arg_pairs) {
		ssc::check_file_name_sanity( pair.second, 1 );
		if (pair.first == "-i" || pair.first == "--input-file")
			input_abstr.input_filename = pair.second;
		else
			extraneous_args.push_back( move( pair ) );
	}
	if (input_abstr.input_filename.empty()) {
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
	using threecrypt::Decryption_Method_e;

	auto mode = Mode_e::None;
	threecrypt::Input_Abstraction input_abstr;
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
			auto const remaining_args = process_encrypt_arguments( std::move( mode_specific_arguments ), input_abstr );
			if (!remaining_args.empty())
				die_unneeded_args( remaining_args );
			threecrypt::cbc_v2::CBC_V2_encrypt( input_abstr );
			}
		break;
		case (Mode_e::Symmetric_Decrypt):
		{
			auto const remaining_args = process_decrypt_arguments( std::move( mode_specific_arguments ),
			input_abstr.input_filename, input_abstr.output_filename );
			if (!remaining_args.empty())
				die_unneeded_args( remaining_args );
			ssc::enforce_file_existence( input_abstr.input_filename.c_str(), true );
			auto const method = threecrypt::determine_decrypt_method( input_abstr.input_filename.c_str() );
			switch (method) {
				default:
					std::fprintf( stderr, "Error: Invalid decrypt method ( %d ).\n", static_cast<int>(method) );
					std::fputs( Help_Suggestion, stderr );
					std::exit( EXIT_FAILURE );
				case (Decryption_Method_e::None):
					std::fprintf( stderr, "Error: the input file `%s` does not appear to be a valid 3crypt encrypted file.\n",
					input_abstr.input_filename.c_str() );
					std::fputs( Help_Suggestion, stderr );
					std::exit( EXIT_FAILURE );
#ifdef CBC_V2_HH
				case (Decryption_Method_e::CBC_V2):
					threecrypt::cbc_v2::CBC_V2_decrypt( input_abstr.input_filename.c_str(), input_abstr.output_filename.c_str() );
					break;
#endif
#ifdef CBC_V1_HH
				case (Decryption_Method_e::CBC_V1):
					threecrypt::cbc_v1::CBC_V1_decrypt( input_abstr.input_filename.c_str(), input_abstr.output_filename.c_str() );
					break;
#endif
			}/* ! switch( method ) */
		}
		break;/* ! case( Mode_e::Symmetric_Decrypt ) */
		case (Mode_e::Dump_Fileheader):
		{
			auto const remaining_args = process_dump_header_arguments( std::move( mode_specific_arguments ), input_abstr );
			if (!remaining_args.empty())
				die_unneeded_args( remaining_args );
			ssc::enforce_file_existence( input_abstr.input_filename.c_str(), true );
			auto const method = threecrypt::determine_decrypt_method( input_abstr.input_filename.c_str() );
			switch (method) {
				default:
				case (Decryption_Method_e::None):
					std::fprintf( stderr, "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n",
						      input_abstr.input_filename.c_str() );
					std::fputs( Help_Suggestion, stderr );
					std::exit( EXIT_FAILURE );
#ifdef CBC_V2_HH
				case (Decryption_Method_e::CBC_V2):
					threecrypt::cbc_v2::dump_header( input_abstr.input_filename.c_str() );
					break;
#endif
#ifdef CBC_V1_HH
				case (Decryption_Method_e::CBC_V1):
					std::fputs( "Error: Dumping CBC_V1 headers not supported.\n", stderr );
					std::exit( EXIT_FAILURE );
					break;
#endif
			}
		}
		break;/* ! case( Mode_e::Dump_Fileheader ) */
	} /* ! switch ( mode ) */

	return EXIT_SUCCESS;
}
