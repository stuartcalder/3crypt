/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "main_control_unit.hh"

#include <type_traits>

#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>

/* Enforce that a valid crypto method has been defined.
 */
#if    (!defined (__SSC_CTR_V1__) && !defined (__SSC_CBC_V2__))
#	error 'CTR_V1 or CBC_V2 must be defined here.'
#endif

/* Enforce that neither OPENBSD_UNVEIL_IO nor OPENBSD_UNVEIL_I have been defined.
 */
#if    defined (OPENBSD_UNVEIL_IO) || defined (OPENBSD_UNVEIL_I)
#	error 'Already defined'
#endif
/* Enable OpenBSD-specific security sandboxing functionalties
 */
#ifdef __OpenBSD__
static void openbsd_unveil_io (char const *input_filename, char const *output_filename)
{
	_OPENBSD_UNVEIL ("/usr","rx"); // Allow reading and executing libssc.
	_OPENBSD_UNVEIL (input_filename,"r"); // Allow reading the input file.
	_OPENBSD_UNVEIL (output_filename,"rwc"); // Allow reading, writing, creating the output file.
	_OPENBSD_UNVEIL (nullptr,nullptr); // Finalize the unveil() calls.
}
static void openbsd_unveil_i (char const *input_filename)
{
	_OPENBSD_UNVEIL ("/usr","rx"); // Allow reading and executing libssc.
	_OPENBSD_UNVEIL (input_filename,"r"); // Allow reading the input file.
	_OPENBSD_UNVEIL (nullptr,nullptr); // Finalize the unveil() calls.
}
/* On OpenBSD systems, the following macros call the above static functions.
 */
#	define OPENBSD_UNVEIL_IO(input,output)	openbsd_unveil_io( input, output )
#	define OPENBSD_UNVEIL_I(input)          openbsd_unveil_i( input )
#else
/* On non-OpenBSD systems, the following macros will do nothing.
 */
#	define OPENBSD_UNVEIL_IO(input,output)
#	define OPENBSD_UNVEIL_I(input)
#endif/*#ifdef __OpenBSD__*/

/* If __SSC_CTR_V1__ has been defined, make CTR_V1 the default crypto implementation,
 * otherwise default to CBC_V2.
 */
#ifdef DEFAULT_IMPL_NS
#	error 'Already defined'
#endif
#if    defined (__SSC_CTR_V1__)
#	define DEFAULT_IMPL_NS	ssc::crypto_impl::ctr_v1
#elif  defined (__SSC_CBC_V2__)
#	define DEFAULT_IMPL_NS	ssc::crypto_impl::cbc_v2
#endif

namespace _3crypt {
	// The constructor of the main control unit is the entry point.
	Main_Control_Unit::Main_Control_Unit (int const arg_count, char const *arg_vect[]) {
		// Process the arguments from the command line, pooling the remaining mode-specific arguments.
		Arg_Map_t mode_specific_arguments = process_mode_arguments_( ssc::Arg_Mapping{ arg_count, arg_vect }.consume(), mode );
		static_assert (std::is_same<decltype(mode), Mode_E>::value);
		switch (mode) {
			default:
			// Disallow an unset mode.
			case (Mode_E::None):
				errx( "Error: No mode selected or invalid mode (%d)\n%s", static_cast<int>(mode), Help_Suggestion );
			// Symmetric file encryption mode.
			case (Mode_E::Symmetric_Encrypt):
				{
					// Process the symmetric file encryption arguments. If there are more arguments left, error out.
					Arg_Map_t const remaining_arguments = process_encrypt_arguments_( std::move( mode_specific_arguments ), input );
					if (!remaining_arguments.empty())
						die_unneeded_arguments_( remaining_arguments );
				}

 				// On OpenBSD, restrict filesystem to what is needed. On all other systems this does nothing.
				OPENBSD_UNVEIL_IO (input.input_filename.c_str(),input.output_filename.c_str());

				DEFAULT_IMPL_NS::encrypt( input );

				break;
			// Symmetric file decryption mode.
			case (Mode_E::Symmetric_Decrypt):
				{
					// Process the symmetric file decryption arguments. If there are more arguments left, error out.
					Arg_Map_t const remaining_arguments = process_decrypt_arguments_( std::move( mode_specific_arguments ), input.input_filename, input.output_filename );
					if (!remaining_arguments.empty())
						die_unneeded_arguments_( remaining_arguments );

					// On OpenBSD, restrict filesystem to what is needed. On all other systems this does nothing.
					OPENBSD_UNVEIL_IO (input.input_filename.c_str(),input.output_filename.c_str());

					// Force the asked-for input file to exist. If it doesn't, error out.
					ssc::enforce_file_existence( input.input_filename.c_str(), true );
					// Determine the decryption method to be used from the header of the input file.
					Crypto_Method_E const crypt_method = ssc::crypto_impl::determine_crypto_method( input.input_filename.c_str() );
					switch (crypt_method) {
						// Disallow there to be no decryption method set.
						default:
							errx( "Error: Invalid decryption method (%d)\n", static_cast<int>(crypt_method) );
						case (Crypto_Method_E::None):
							errx( "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n%s",
							      input.input_filename.c_str(), Help_Suggestion );
#ifdef __SSC_CBC_V2__
						// CBC_V2 decrypt, according to the input and output std::string filenames.
						case (Crypto_Method_E::CBC_V2):
							ssc::crypto_impl::cbc_v2::decrypt( input.input_filename.c_str(), input.output_filename.c_str() );
							break;
#endif
#ifdef __SSC_CTR_V1__
						case (Crypto_Method_E::CTR_V1):
							ssc::crypto_impl::ctr_v1::decrypt( input.input_filename.c_str(), input.output_filename.c_str() );
							break;
#endif
					}/*switch (method)*/
				}
				break;
			// Dump headers from symmetrically encrypted files.
			case (Mode_E::Dump_Fileheader):
				{
					// Process the "dump header" arguments. Error out if any arguments remain.
					Arg_Map_t const remaining_arguments = process_dump_header_arguments_( std::move( mode_specific_arguments ), input.input_filename );
					if (!remaining_arguments.empty())
						die_unneeded_arguments_( remaining_arguments );

					// On OpenBSD, restrict filesystem to what is needed. On all other systems this does nothing.
					OPENBSD_UNVEIL_I (input.input_filename.c_str());

					// Force the input file specified to exist. If it doesn't exist, error out.
					ssc::enforce_file_existence( input.input_filename.c_str(), true );
					// Determine the decryption method from the std::string input filename.
					Crypto_Method_E const method = ssc::crypto_impl::determine_crypto_method( input.input_filename.c_str() );
					switch (method) {
						default:
						// Disallow there to be no valid decryption method detected.
						case (Crypto_Method_E::None):
							errx( "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n%s", input.input_filename.c_str(), Help_Suggestion );
#ifdef __SSC_CBC_V2__
						// CBC_V2 fileheader dump, according to the input std::string filename.
						case (Crypto_Method_E::CBC_V2):
							ssc::crypto_impl::cbc_v2::dump_header( input.input_filename.c_str() );
							break;
#endif
#ifdef __SSC_CTR_V1__
						case (Crypto_Method_E::CTR_V1):
							ssc::crypto_impl::ctr_v1::dump_header( input.input_filename.c_str() );
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
		// Return arguments unrelated to determining the mode in `extraneous_arguments`.
		Arg_Map_t extraneous_arguments;
		_CTIME_CONST (auto) Mode_Already_Set = "Error: Program mode already set\n"
		 		  	              "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";
		// For each argument after the first, which is the name of the 3crypt executable.
		for (size_t i = 1; i < in_map.size(); ++i) {
			// -e and --encrypt designate symmetric file encryption.
			if (in_map[ i ].first == "-e" || in_map[ i ].first == "--encrypt") {
				// Disallow setting a mode after we've already set one.
				if (mode != Mode_E::None)
					errx( "%s\n%s\n", Mode_Already_Set, Help_Suggestion );
				mode = Mode_E::Symmetric_Encrypt;
			// -d and --decrypt designate symmetric file decryption.
			} else if (in_map[ i ].first == "-d" || in_map[ i ].first == "--decrypt") {
				// Disallow setting a mode after we've already set one.
				if (mode != Mode_E::None)
					errx( "%s\n%s\n", Mode_Already_Set, Help_Suggestion );
				mode = Mode_E::Symmetric_Decrypt;
			// --dump-header designates dumping the headers of a 3crypt encrypted file.
			} else if (in_map[ i ].first == "-D" || in_map[ i ].first == "--dump") {
				// Disallow setting a mode after we've already set one.
				if (mode != Mode_E::None)
					errx( "%s\n%s\n", Mode_Already_Set, Help_Suggestion );
				mode = Mode_E::Dump_Fileheader;
			// -h and --help designate printing help info and then exitting, successfully and without error.
			} else if (in_map[ i ].first == "-h" || in_map[ i ].first == "--help") {
				fputs( Help_String, stdout );
				exit( EXIT_SUCCESS );
			// Disallow there to be an empty first argument and nonempty second argument in an argument pair.
			} else if (in_map[ i ].first.empty() && !(in_map[ i ].second.empty())) {
				errx( "Error: Floating arguments (%s) not allowed\n%s", in_map[ i ].second.c_str(), Help_Suggestion );
			// Prepare to return the unrelated arguments in `extraneous_arguments`.
			} else {
				extraneous_arguments.push_back( std::move( in_map[ i ] ) );
			}
		}/*for(size_t i=1;i<in_map.size();++i)*/
		// Return the unused arguments.
		return extraneous_arguments;
	}/*process_mode_arguments_(Arg_Map_t&&,Mode_E&)*/

	Arg_Map_t
	Main_Control_Unit::process_encrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, Default_Input_t &encr_input) {
		// Prepare to return unused arguments in `extraneous_arguments`.
		Arg_Map_t extraneous_arguments;

		static_assert (std::is_same<Default_Input_t, ssc::crypto_impl::Input>::value);
		// Clear the input and output file names.
		encr_input.input_filename.clear();
		encr_input.output_filename.clear();
		// Default the number of sspkdf iterations and concatenations to the header prescribed defaults.
		encr_input.number_sspkdf_iterations     = Default_Iterations;
		encr_input.number_sspkdf_concatenations = Default_Concatenations;
		// By default, do not supplement OS provided entropy from the keyboard.
		encr_input.supplement_os_entropy = false;

		// For every argument pair in `opt_arg_pairs`
		for (auto &&pair : opt_arg_pairs) {
			// Get the input filename.
			if (pair.first == "-i" || pair.first == "--input") {
				// Force the provided input file name to be valid.
				ssc::check_file_name_sanity( pair.second, 1 );
				encr_input.input_filename = pair.second;
				// If there isn't a specified output file yet, default the output filename to be <input_filename>.3c
				if (encr_input.output_filename.empty()) 
					encr_input.output_filename = encr_input.input_filename + ".3c";
			// Get the output filename.
			} else if (pair.first == "-o" || pair.first == "--output" ) {
				// Force the provided output file name to be valid.
				ssc::check_file_name_sanity( pair.second, 1 );
				encr_input.output_filename = pair.second;
			// Get the sspkdf iteration count.
			} else if (pair.first == "--iter-count") {
				// At maximum, allow there to be 10 string characters.
				_CTIME_CONST (decltype(pair.second.size())) Max_Count_Chars = 10;
				ssc::check_file_name_sanity( pair.second, 1 );
				std::string count = std::move( pair.second );
				if (count.size() > Max_Count_Chars)
					errx( "Error: The specified iteration count (%s) is too large.\n%s", count.c_str(), Help_Suggestion );
				// Read all the '0-9' digits from count, forming an integer out of it.
				if (ssc::enforce_integer( count )) {
					auto const num_iter = static_cast<u32_t>(atoi( count.c_str() ));
					if (num_iter == 0)
						errx( "Error: Number iterations specified is zero.\n" );
					// Set the number of times to iterate to the integer we got from the command line.
					encr_input.number_sspkdf_iterations = num_iter;
				}
			// Get the sspkdf concatenation count.
			} else if (pair.first == "--concat-count") {
				// At maximum, allow there to be 10 string characters.
				_CTIME_CONST (decltype(pair.second.size())) Max_Count_Chars = 10;
				ssc::check_file_name_sanity( pair.second, 1 );
				std::string count = std::move( pair.second );
				if (count.size() > Max_Count_Chars)
					errx( "Error: The specified concatenation count (%s) is too large.\n%s", count.c_str(), Help_Suggestion );
				// Read all the '0-9' digits from count, forming an integer out of it.
				if (ssc::enforce_integer( count )) {
					auto num_concat = static_cast<u32_t const>(atoi( count.c_str() ));
					if (num_concat == 0)
						errx( "Error: Number concatenations specified is zero.\n" );
					// Set the number of time to concatenate to the integer we got from the command line.
					encr_input.number_sspkdf_concatenations = num_concat;
				}
			// Get supplementary entropy from the keyboard to help seed the Skein-based CSPRNG.
			} else if (pair.first == "-E" || pair.first == "--entropy") {
				encr_input.supplement_os_entropy = true;
			// Prepare to return all the unrelated arguments.
			} else {
				extraneous_arguments.push_back( std::move( pair ) );
			}
		}/*for(auto&&:opt_arg_pairs)*/
		// Return all the unrelated arguments.
		return extraneous_arguments;
	}/*process_encrypt_arguments_(Arg_Map_t&&,Default_Input_t&)*/

	Arg_Map_t
	Main_Control_Unit::process_decrypt_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &input_filename, std::string &output_filename) {
		using namespace std;
		// Prepare to return all the unused arguments.
		Arg_Map_t extraneous_arguments;

		// Clear the input and output file names.
		input_filename.clear();
		output_filename.clear();

		// For every pair in `opt_arg_pairs`
		for (auto &&pair : opt_arg_pairs) {
			// Force the second std::string of every pair to be valid.
			ssc::check_file_name_sanity( pair.second, 1 );
			// Get the input file name.
			if (pair.first == "-i" || pair.first == "--input") {
				input_filename = pair.second;
				// If the input filename was postfixed with .3c and no output filename has yet been specified, assume the original without ".3c" postfixed.
				if (output_filename.empty() && (input_filename.size() >= 4) && (input_filename.substr( input_filename.size() - 3 ) == ".3c"))
					output_filename = input_filename.substr( 0, input_filename.size() - 3 );
			// Get the output file name.
			} else if (pair.first == "-o" || pair.first == "--output") {
				output_filename = pair.second;
			// Prepare to return unrelated arguments.
			} else {
				extraneous_arguments.push_back( std::move( pair ) );
			}
		}/*for(auto &&pair:opt_arg_pairs)*/
		// Disallow either the input or output filenames to be zero-length.
		if (input_filename.empty())
			errx( "Error: The input filename was not specified (zero length filenames disallowed)\n" );
		if (output_filename.empty())
			errx( "Error: The output filename was not specified (zero length filenames disallowed)\n" );
		// Return the unrelated arguments.
		return extraneous_arguments;
	}/*process_decrypt_arguments_(Arg_Mapt_t&&,std::string&,std::string&)*/

	Arg_Map_t
	Main_Control_Unit::process_dump_header_arguments_ (Arg_Map_t &&opt_arg_pairs, std::string &filename) {
		using namespace std;

		// Prepare to return the unrelated arguments.
		Arg_Map_t extraneous_arguments;

		// For every pair in `opt_arg_pairs`.
		for (auto &&pair : opt_arg_pairs) {
			// Force the second std::string of every pair to be valid.
			ssc::check_file_name_sanity( pair.second, 1 );
			// Get the name of the input file, or prepare to return the unrelated arguments.
			if (pair.first == "-i" || pair.first == "--input")
				filename = pair.second;
			else
				extraneous_arguments.push_back( move( pair ) );
		}/*for(auto &&pair:opt_arg_pairs)*/
		// Disallow the filename from being zero-length.
		if (filename.empty())
			errx( "Error: Input filename not specified for file-header dump.\n%s", Help_Suggestion );
		// Return the unrelated arguments.
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

#undef DEFAULT_IMPL_NS
#undef OPENBSD_UNVEIL_IO
#undef OPENBSD_UNVEIL_I
