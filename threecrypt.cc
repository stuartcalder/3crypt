#include <limits>
#include <cctype>
#include <ssc/files/os_map.hh>
#include "threecrypt.hh"

#if     defined (OPENBSD_UNVEIL_I) || defined (OPENBSD_UNVEIL_IO) || defined (SETUP_MAPS) \
     || defined (ENCRYPT_INPUT)
#	error 'Some MACRO we need was already defined'
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

#if    defined (__SSC_DRAGONFLY_V1__)
#	define ENCRYPT_INPUT Catena_Input
#elif  defined (__SSC_CBC_V2__)
#	define ENCRYPT_INPUT SSPKDF_Input
#else
#	error 'No supported crypto method detected.'
#endif

using namespace ssc::crypto_impl;
using namespace ssc;

#ifdef __SSC_DRAGONFLY_V1__
static inline u8_t dragonfly_parse_memory (std::string mem)
{
	u64_t requested_bytes = 0;
	u64_t multiplier = 1;
	for( char c : mem ) {
		switch( std::toupper( static_cast<unsigned char>(c) ) ) {
		case( 'K' ):
			multiplier = (1'024 / 64);
			goto Have_Mul_L;
		case( 'M' ):
			multiplier = (1'048'576 / 64);
			goto Have_Mul_L;
		case( 'G' ):
			multiplier = (1'073'741'824 / 64);
			goto Have_Mul_L;
		}
	}
Have_Mul_L:
	constexpr auto Max_Digits = [](u64_t m) constexpr -> int {
		int num_digits = 0;
		while( m > 0 ) {
			m /= 10;
			++num_digits;
		}
		return num_digits;
	};
	_CTIME_CONST (int)   B_Max_Digits = 1'000;
	_CTIME_CONST (u64_t) K_Max = (std::numeric_limits<u64_t>::max)() / 1'024;         // 2^10
	_CTIME_CONST (int)   K_Max_Digits = Max_Digits (K_Max);
	_CTIME_CONST (u64_t) M_Max = (std::numeric_limits<u64_t>::max)() / 1'048'576;     // 2^20
	_CTIME_CONST (int)   M_Max_Digits = Max_Digits (M_Max);
	_CTIME_CONST (u64_t) G_Max = (std::numeric_limits<u64_t>::max)() / 1'073'741'824; // 2^30
	_CTIME_CONST (int)   G_Max_Digits = Max_Digits (G_Max);
	if( enforce_integer( mem ) ) {
		switch( multiplier ) {
		case( 1 ):
			if( mem.size() > B_Max_Digits )
				errx( "Error: Specified memory parameter is too large!\n" );
			break;
		case( 1'024 ):
			if( mem.size() > K_Max_Digits )
				errx( "Error: Specified memory parameter is too large!\n" );
			break;
		case( 1'048'576 ):
			if( mem.size() > M_Max_Digits )
				errx( "Error: Specified memory parameter is too large!\n" );
			break;
		case( 1'073'741'824 ):
			if( mem.size() > G_Max_Digits )
				errx( "Error: Specified memory parameter is too large!\n" );
			break;
		}
	} else {
		errx( "Error: No number supplied with memory-usage specification.\n" );
	}
	requested_bytes = std::strtoull( mem.c_str(), nullptr, 10 );
	requested_bytes *= multiplier;
	if( requested_bytes == 0 )
		errx( "Error: Zero memory requested?\n" );
	u64_t mask   = 0x80'00'00'00'00'00'00'00; // Leading 1 bit, the rest 0.
	u8_t  garlic = 63;
	while( !(mask & requested_bytes) ) {
		mask >>= 1;
		--garlic;
	}
	return garlic;

}
static inline u8_t dragonfly_parse_iterations (std::string mem)
{
	if( enforce_integer( mem ) ) {
		if( mem.size() > 3 )
			errx( "Error: Too many characters specifying the iteration count.\n" );
		int it = std::atoi( mem.c_str() );
		if( it < 1 || it > 255 )
			errx( "Error: Invalid iteration count\n" );
		return static_cast<u8_t>(it);
	} else {
		errx( "Error: Invalid iteration count\n" );
		return static_cast<u8_t>(0); // Stop compiler complaining about no return value.
	}
}
static inline u64_t dragonfly_parse_padding (std::string padding)
{
	u64_t multiplier = 1;
	for( char c : padding ) {
		switch( std::toupper( static_cast<unsigned char>(c) ) ) {
		case( 'K' ):
			multiplier = 1'024;
			goto Have_Mul_L;
		case( 'M' ):
			multiplier = (1'024 * 1'024);
			goto Have_Mul_L;
		case( 'G' ):
			multiplier = (1'024 * 1'024 * 1'024);
			goto Have_Mul_L;
		}
	}
Have_Mul_L:
	if( enforce_integer( padding ) ) {
		unsigned long long p = std::strtoull( padding.c_str(), nullptr, 10 );
		return static_cast<u64_t>(p) * multiplier;
	} else {
		errx( "Error: Asked for padding, without providing a number of padding bytes.\n" );
		return static_cast<u64_t>(0); // Stop compiler complaining about no return value.
	}
}
#endif /* ~ #ifdef __SSC_DRAGONFLY_V1__ */

struct Threecrypt_Data {
#if    defined (__SSC_DRAGONFLY_V1__)
	Catena_Input catena_input;
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
		if( threecrypt_data.output_filename.empty() )
			threecrypt_data.output_filename = threecrypt_data.input_filename + ".3c";
		OPENBSD_UNVEIL_IO (threecrypt.input_filename.c_str(),
				   threecrypt.output_filename.c_str());
		// Setup input map.
		threecrypt_data.input_map.os_file = open_existing_os_file( threecrypt_data.input_filename.c_str(), true );
		threecrypt_data.input_map.size = get_file_size( threecrypt_data.input_map.os_file );
		map_file( threecrypt_data.input_map, true );
		// Setup output map.
		threecrypt_data.output_map.os_file = create_os_file( threecrypt_data.output_filename.c_str() );
		process_encrypt_arguments( argument_state, threecrypt_data );
		if( !argument_state.empty() )
			die_unneeded_arguments( argument_state );
#if    defined (__SSC_DRAGONFLY_V1__)
		if( threecrypt_data.catena_input.g_low > threecrypt_data.catena_input.g_high )
			threecrypt_data.catena_input.g_high = threecrypt_data.catena_input.g_low;
		if( threecrypt_data.catena_input.lambda == 0 )
			threecrypt_data.catena_input.lambda = 1;
		dragonfly_v1::encrypt( threecrypt_data.catena_input,
				       threecrypt_data.input_map,
				       threecrypt_data.output_map,
				       threecrypt_data.output_filename.c_str() );
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
#ifdef __SSC_DRAGONFLY_V1__
			case( Crypto_Method_E::Dragonfly_V1 ):
				{
					threecrypt_data.output_map.os_file = create_os_file( threecrypt_data.output_filename.c_str() );
					dragonfly_v1::decrypt( threecrypt_data.input_map,
							       threecrypt_data.output_map,
							       threecrypt_data.output_filename.c_str() );
					return;
				}
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				{
					threecrypt_data.output_map.os_file = create_os_file( threecrypt_data.output_filename.c_str() );
					cbc_v2::decrypt( threecrypt_data.input_map,
							 threecrypt_data.output_map,
							 threecrypt_data.output_filename.c_str() );
					return;
				}
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
#ifdef __SSC_DRAGONFLY_V1__
			case( Crypto_Method_E::Dragonfly_V1 ):
				{
					dragonfly_v1::dump_header( threecrypt_data.input_map, threecrypt_data.input_filename.c_str() );
					return;
				}
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				{
					cbc_v2::dump_header( threecrypt_data.input_map, threecrypt_data.input_filename.c_str() );
					return;
				}
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
#if    defined (__SSC_DRAGONFLY_V1__)
	tc_data.catena_input.padding_bytes = 0;
	tc_data.catena_input.supplement_os_entropy = false;
	tc_data.catena_input.g_low   = 23; // Default to ~ 512MB of memory usage
	tc_data.catena_input.g_high  = 23;
	tc_data.catena_input.lambda  = 1;
	tc_data.catena_input.use_phi = 0;
#elif  defined (__SSC_CBC_V2__)
	tc_data.sspkdf_input.supplement_os_entropy = false;
	tc_data.sspkdf_input.number_iterations = 3'000'000;
	tc_data.sspkdf_input.number_concatenations = 3'000'000;
	_CTIME_CONST (int) Max_Chars = 10;
#else
#	error 'No valid crypto method detected'
#endif
	Arg_Map_t extraneous_args;
	for( auto &&pair : argument_map ) {
		if( pair.first == "-E" || pair.first == "--entropy" ) {
#if    defined (__SSC_DRAGONFLY_V1__)
			tc_data.catena_input.supplement_os_entropy = true;
#elif  defined (__SSC_CBC_V2__)
			tc_data.sspkdf_input.supplement_os_entropy = true;
#else
#	error 'No supported crypto method detected.'
#endif
		}
#if    defined (__SSC_DRAGONFLY_V1__)
		else if( pair.first == "--min-memory" ) {
			tc_data.catena_input.g_low  = dragonfly_parse_memory( std::move( pair.second ) );
		} else if( pair.first == "--max-memory" ) {
			tc_data.catena_input.g_high = dragonfly_parse_memory( std::move( pair.second ) );
		} else if( pair.first == "--use-memory" ) {
			tc_data.catena_input.g_high = dragonfly_parse_memory( std::move( pair.second ) );
			tc_data.catena_input.g_low = tc_data.catena_input.g_high;
		} else if( pair.first == "--iterations" ) {
			tc_data.catena_input.lambda = dragonfly_parse_iterations( std::move( pair.second ) );
		} else if( pair.first == "--use-phi" ) {
			tc_data.catena_input.use_phi = 1;
		} else if( pair.first == "--pad-by" ) {
			tc_data.catena_input.padding_bytes = dragonfly_parse_padding( std::move( pair.second ) );
		} else if( pair.first == "--pad-to" ) {
			u64_t target = dragonfly_parse_padding( std::move( pair.second ) );
			if( target < ssc::crypto_impl::dragonfly_v1::Visible_Metadata_Bytes ) {
				unmap_file( tc_data.input_map );
				close_os_file( tc_data.output_map.os_file );
				close_os_file( tc_data.input_map.os_file );
				remove( tc_data.output_filename.c_str() );
				errx( "Error: The --pad-to target (%" PRIu64 ") is way too small!\n", target );
			}
			if( (target - ssc::crypto_impl::dragonfly_v1::Visible_Metadata_Bytes) < tc_data.input_map.size ) {
				unmap_file( tc_data.input_map );
				close_os_file( tc_data.output_map.os_file );
				close_os_file( tc_data.input_map.os_file );
				remove( tc_data.output_filename.c_str() );
				errx( "Error: The input map size (%" PRIu64 ") is too large to --pad-to %" PRIu64 "\n", tc_data.input_map.size, target );
			} else {
				tc_data.catena_input.padding_bytes = target;
				tc_data.catena_input.padding_bytes -= tc_data.input_map.size;
				tc_data.catena_input.padding_bytes -= ssc::crypto_impl::dragonfly_v1::Visible_Metadata_Bytes;
			}
		}
#elif  defined (__SSC_CBC_V2__)
		else if( pair.first == "--iter-count" ) {
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
		}
#else
#	error 'No supported crypto method detected.'
#endif
		else {
			extraneous_args.push_back( std::move( pair ) );
		}
	}/* ~ for (auto &&pair : argument_map) */
	argument_map = extraneous_args;
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
#undef ENCRYPT_INPUT
#undef SETUP_MAPS
#undef OPENBSD_UNVEIL_IO
#undef OPENBSD_UNVEIL_I
