#include <ssc/files/os_map.hh>
#include "threecrypt.hh"

#if     defined (OPENBSD_UNVEIL_I) || defined (OPENBSD_UNVEIL_IO) || \
	defined (DEFAULT_IMPL_NS)
#	error 'Some MACRO we need was already defined'
#endif

#if    defined (__SSC_CTR_V1__)
#	define DEFAULT_IMPL_NS ctr_v1
#elif  defined (__SSC_CBC_V2__)
#	define DEFAULT_IMPL_NS cbc_v2
#else
#	error 'No supported crypto impl detected'
#endif

#ifdef __OpenBSD__
#	define OPENBSD_UNVEIL_I(input_fname) \
		_OPENBSD_UNVEIL ("/usr","rx"); \
		_OPENBSD_UNVEIL (input_fname,"r"); \
		_OPENBSD_UNVEIL (nullptr,nullptr)
#	define OPENBSD_UNVEIL_IO(input_fname,output_fname) \
		_OPENBSD_UNVEIL ("/usr","rx"); \
		_OPENBSD_UNVEIL (input_fname,"r"); \
		_OPENBSD_UNVEIL (output_fname,"rwc"); \
		_OPENBSD_UNVEIL (nullptr,nullptr)
#else
#	define OPENBSD_UNVEIL_I(none_0)
#	define OPENBSD_UNVEIL_IO(none_0,none_1)
#endif

#define SETUP_MAPS(tc_data,setup_input_bool,setup_output_bool) \
		if constexpr (setup_input_bool) { \
			tc_data.input_map.os_file = open_existing_os_file( tc_data.input_filename.c_str(), true ); \
			tc_data.input_map.size = get_file_size( tc_data.input_map.os_file ); \
			map_file( tc_data.input_map, true ); \
		} \
		if constexpr (setup_output_bool) \
			tc_data.output_map.os_file = create_os_file( tc_data.output_filename.c_str() )

using namespace ssc::crypto_impl;
using namespace ssc;

struct Threecrypt_Data {
#if    defined (__SSC_CTR_V1__)
	/*TODO*/
#elif  defined (__SSC_CBC_V2__)
	SSPKDF_Input sspkdf_input;
#else
#	error 'No valid crypto method detected'
#endif
	OS_Map      input_map;
	OS_Map      output_map;
	std::string input_filename;
	std::string output_filename;
	Mode_E      mode;
};

_CTIME_CONST (auto) Mode_Already_Set = "Error: Program mode already set\n"
				      "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n";

static inline void      set_mode                      (Threecrypt_Data &tc_data , Mode_E mode             );
static inline Arg_Map_t process_io_arguments          (Arg_Map_t &&argument_map, Threecrypt_Data &tc_data);
static inline void      process_mode_arguments        (Arg_Map_t &argument_map , Threecrypt_Data &tc_data);
static inline void      process_encrypt_arguments     (Arg_Map_t &argument_map , Threecrypt_Data &tc_data);
static inline void      process_decrypt_arguments     (Threecrypt_Data &tc_data);
static        void      die_unneeded_arguments        (Arg_Map_t const &arg_map);

void threecrypt (int const argc, char const *argv[])
{
	Threecrypt_Data threecrypt_data; // Threecrypt data to be passed around this function as needed.
	threecrypt_data.mode = Mode_E::None;
	Arg_Map_t argument_state = process_io_arguments( Arg_Mapping{ argc, argv }.consume(), threecrypt_data );
	process_mode_arguments( argument_state, threecrypt_data );
	switch( threecrypt_data.mode ) {
	default:
	case( Mode_E::None ):
		{
			errx( "Error: No mode selected or invalid mode (%d)\n%s", static_cast<int>(threecrypt_data.mode), Help_Suggestion );
		}
	case( Mode_E::Symmetric_Encrypt ):
		{
			process_encrypt_arguments( argument_state, threecrypt_data );
			if( !argument_state.empty() )
				die_unneeded_arguments( argument_state );
			OPENBSD_UNVEIL_IO (threecrypt.input_filename.c_str(),
					   threecrypt.output_filename.c_str());
			SETUP_MAPS (threecrypt_data,true,true);
#if    defined (__SSC_CTR_V1__)
			/*TODO*/
#elif  defined (__SSC_CBC_V2__)
			cbc_v2::encrypt( threecrypt_data.sspkdf_input,
					 threecrypt_data.input_map,
					 threecrypt_data.output_map );
#else
#	error 'No supported method detected'
#endif
			return;
		}
	case( Mode_E::Symmetric_Decrypt ):
		{
			process_decrypt_arguments( threecrypt_data );

			if( !argument_state.empty() )
				die_unneeded_arguments( argument_state );

			OPENBSD_UNVEIL_IO (threecrypt_data.input_filename.c_str(),
					   threecrypt_data.output_filename.c_str());

			SETUP_MAPS (threecrypt_data,true,false);

			Crypto_Method_E method = determine_crypto_method( threecrypt_data.input_map );
			switch( method ) {
			default:
				{
					unmap_file( threecrypt_data.input_map );
					close_os_file( threecrypt_data.input_map.os_file );
					errx( "Error: Invalid decryption method (%d)\n", static_cast<int>(method) );
				}
			case( Crypto_Method_E::None ):
				{
					unmap_file( threecrypt_data.input_map );
					close_os_file( threecrypt_data.input_map.os_file );
					errx( "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n%s",
					      threecrypt_data.input_filename.c_str(), Help_Suggestion );
				}
#ifdef __SSC_CTR_V1__
			case( Crypto_Method_E::CTR_V1 ):
				/*TODO*/
				return;
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				{
					threecrypt_data.output_map.os_file = create_os_file( threecrypt_data.output_filename.c_str() );
					cbc_v2::decrypt( threecrypt_data.input_map,
							 threecrypt_data.output_map,
							 threecrypt_data.output_filename.c_str() );
				}
				return;
#endif
			}
			break;
		}
	case( Mode_E::Dump_Fileheader ):
		{
			if( !argument_state.empty() )
				die_unneeded_arguments( argument_state );
			OPENBSD_UNVEIL_I (threecrypt_data.input_filename.c_str());
			SETUP_MAPS (threecrypt_data,true,false);

			Crypto_Method_E method = determine_crypto_method( threecrypt_data.input_map );
			switch( method ) {
			default:
				{
					unmap_file( threecrypt_data.input_map );
					close_os_file( threecrypt_data.input_map.os_file );
					errx( "Error: Invalid decryption method (%d)\n", static_cast<int>(method) );
				}
			case( Crypto_Method_E::None ):
				{
					unmap_file( threecrypt_data.input_map );
					close_os_file( threecrypt_data.input_map.os_file );
					errx( "Error: The input file `%s` does not appear to be a valid 3crypt encrypted file.\n%s",
					      threecrypt_data.input_filename.c_str(), Help_Suggestion );
				}
#ifdef __SSC_CTR_V1__
			case( Crypto_Method_E::CTR_V1 ):
				/*TODO*/
				return;
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				cbc_v2::dump_header( threecrypt_data.input_map, threecrypt_data.input_filename.c_str() );
				return;
#endif
			}

			return;
		}
	}
}

inline void set_mode (Threecrypt_Data &tc_data , Mode_E mode )
{
	if( tc_data.mode != Mode_E::None )
		errx( "%s\n%s\n", Mode_Already_Set, Help_Suggestion );
	tc_data.mode = mode;
}

Arg_Map_t process_io_arguments (Arg_Map_t &&in_map, Threecrypt_Data &tc_data)
{
	Arg_Map_t extraneous_args;
	for( int i = 1; i < in_map.size(); ++i ) {
		if( in_map[ i ].first == "-i" || in_map[ i ].first == "--input" ) {
			check_file_name_sanity( in_map[ i ].second, 1 );
			tc_data.input_filename = in_map[ i ].second;
		} else if( in_map[ i ].first == "-o" || in_map[ i ].first == "--output" ) {
			check_file_name_sanity( in_map[ i ].second, 1 );
			tc_data.output_filename = in_map[ i ].second;
		} else if( in_map[ i ].first == "-h" || in_map[ i ].first == "--help" ) {
			fputs( Help_String, stdout );
			exit( EXIT_SUCCESS );
		} else if( in_map[ i ].first.empty() && !in_map[ i ].second.empty() ) {
			errx( "Error: Floating arguments (%s) not allowed\n%s", in_map[ i ].second.c_str(), Help_Suggestion );
		} else {
			extraneous_args.push_back( std::move( in_map[ i ] ) );
		}
	}
	return extraneous_args;
}
void process_mode_arguments (Arg_Map_t &argument_map, Threecrypt_Data &tc_data)
{
	Arg_Map_t extraneous_args;
	for( auto &&pair : argument_map ) {
		if( pair.first == "-e" || pair.first == "--encrypt" ) {
			set_mode( tc_data, Mode_E::Symmetric_Encrypt );
		} else if( pair.first == "-d" || pair.first == "--decrypt" ) {
			set_mode( tc_data, Mode_E::Symmetric_Decrypt );
		} else if( pair.first == "-D" || pair.first == "--dump" ) {
			set_mode( tc_data, Mode_E::Dump_Fileheader );
		} else {
			extraneous_args.push_back( std::move( pair ) );
		}
	}
	argument_map = extraneous_args;
}
void process_encrypt_arguments (Arg_Map_t &argument_map, Threecrypt_Data &tc_data)
{
	if( tc_data.output_filename.empty() )
		tc_data.output_filename = tc_data.input_filename + ".3c";
#if    defined (__SSC_CTR_V1__)
	/*TODO*/
#elif  defined (__SSC_CBC_V2__)
	tc_data.sspkdf_input.number_iterations = 1'000'000;
	tc_data.sspkdf_input.number_concatenations = 1'000'000;
	tc_data.sspkdf_input.supplement_os_entropy = false;
#else
#	error 'No valid crypto method detected'
#endif
	Arg_Map_t extraneous_args;
#if    defined (__SSC_CTR_V1__)
		/*TODO*/
#elif  defined (__SSC_CBC_V2__)
	_CTIME_CONST (int) Max_Chars = 10;
	for( auto &&pair : argument_map ) {
		if( pair.first == "--iter-count" ) {
			check_file_name_sanity( pair.second, 1 );
			std::string count = std::move( pair.second );
			if( count.size() > Max_Chars )
				errx( "Error: The specified sspkdf iteration count (%s) is too large.\n%s", count.c_str(), Help_Suggestion );
			if( enforce_integer( count ) ) {
				u32_t const num_iter = static_cast<u32_t>(atoi( count.c_str() ));
				if( num_iter == 0 )
					errx( "Error: Number sspkdf iterations specified is zero.\n" );
				tc_data.sspkdf_input.number_iterations = num_iter;
			}
		} else if( pair.first == "--concat-count" ) {
			check_file_name_sanity( pair.second, 1 );
			std::string count = std::move( pair.second );
			if( count.size() > Max_Chars )
				errx( "Error: The specified sspkdf concatenation count (%s) is too large.\n%s", count.c_str(), Help_Suggestion );
			if( enforce_integer( count ) ) {
				u32_t const num_concat = static_cast<u32_t>(atoi( count.c_str() ));
				if( num_concat == 0 )
					errx( "Error: Number sspkdf concatenations specified is zero.\n" );
				tc_data.sspkdf_input.number_concatenations = num_concat;
			}
		} else if( pair.first == "-E" || pair.first == "--entropy" ) {
			tc_data.sspkdf_input.supplement_os_entropy = true;
		} else {
			extraneous_args.push_back( std::move( pair ) );
		}
	}
	argument_map = extraneous_args;
#else
#	error 'No valid crypto method detected'
#endif
}
void process_decrypt_arguments (Threecrypt_Data &tc_data)
{
	if( tc_data.output_filename.empty() && (tc_data.input_filename.size() >= 4)
	    && (tc_data.input_filename.substr( tc_data.input_filename.size() - 3 ) == ".3c") )
	{
		tc_data.output_filename = tc_data.input_filename.substr( 0, tc_data.input_filename.size() - 3 );
	}
}
void die_unneeded_arguments (Arg_Map_t const &arg_map)
{
	fprintf( stderr, "Error: Unneeded or illegal options or arguments: " );
	for (auto const &pair : arg_map)
		fprintf( stderr, "%s -> %s, ", pair.first.c_str(), pair.second.c_str() );
	fputc( '\n', stderr );
	errx( "%s\n", Help_Suggestion );
}
#undef SETUP_MAPS
#undef OPENBSD_UNVEIL_IO
#undef OPENBSD_UNVEIL_I
#undef DEFAULT_IMPL_NS
