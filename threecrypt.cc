#include <limits>
#include <type_traits>
#include <cctype>
#include <cstdlib>
#include <ssc/files/os_map.hh>
#include <ssc/general/error_conditions.hh>
#include "threecrypt.hh"
using namespace ssc;
using namespace ssc::crypto_impl;

static void set_mode (Threecrypt_Data &tc_data, Mode_E mode); // Prototype
static bool all_strings_are_consumed (char const **, int const);// Prototype

#ifdef __SSC_DRAGONFLY_V1__
enum Multipliers : u64_t {
	Kibibyte = 1'024,
	Mebibyte = Kibibyte * 1'024,
	Gibibyte = Mebibyte * 1'024
};
static constexpr int Get_Max_Digits (u64_t m) {
	int digits = 0;
	while( m > 0 ) {
		m /= 10;
		++digits;
	}
	return digits;
}
u8_t dragonfly_parse_memory (_RESTRICT (char const *) mem_c_str,
		             _RESTRICT (char *)       temp,
			     int const                size)
{
	u64_t requested_bytes = 0;
	u64_t multiplier = 1;
	std::memcpy( temp, mem_c_str, (size + 1) );
	for( int i = 0; i < size; ++i ) {
		switch( std::toupper( static_cast<unsigned char>(mem_c_str[ i ]) ) ) {
		case( 'K' ):
			multiplier = (Kibibyte / 64);
			goto Have_Mul_L;
		case( 'M' ):
			multiplier = (Mebibyte / 64);
			goto Have_Mul_L;
		case( 'G' ):
			multiplier = (Gibibyte / 64);
			goto Have_Mul_L;
		}
	}
Have_Mul_L:
	int num_digits = shift_left_digits( temp, size );
	if( num_digits == 0 )
		errx( "Error: No number supplied with memory-usage specification!\n" );
	_CTIME_CONST (u64_t) U64_Max = (std::numeric_limits<u64_t>::max)();
	enum Max_Digits : int {
		Byte_Max = 1'000,
		Kibibyte_Max = Get_Max_Digits (U64_Max / Kibibyte),
		Mebibyte_Max = Get_Max_Digits (U64_Max / Mebibyte),
		Gibibyte_Max = Get_Max_Digits (U64_Max / Gibibyte)
	};
	_CTIME_CONST (auto&) Invalid_Mem_Param = "Error: Specified memory parameter is too large!\n";
	switch( multiplier ) {
	case 1:
		if( num_digits > Byte_Max )
			errx( Invalid_Mem_Param );
		break;
	case Kibibyte:
		if( num_digits > Kibibyte_Max )
			errx( Invalid_Mem_Param );
		break;
	case Mebibyte:
		if( num_digits > Mebibyte_Max )
			errx( Invalid_Mem_Param );
		break;
	case Gibibyte:
		if( num_digits > Gibibyte_Max )
			errx( Invalid_Mem_Param );
		break;
	}
	static_assert (
		(std::is_same<u64_t,unsigned long int>::value ||
		std::is_same<u64_t,unsigned long long int>::value),
		"We require u64_t to be one of these."
	);
	if constexpr (std::is_same<u64_t,unsigned long int>::value) {
		requested_bytes = std::strtoul( temp, nullptr, 10 );
	} else if constexpr (std::is_same<u64_t,unsigned long long int>::value) {
		requested_bytes = std::strtoull( temp, nullptr, 10 );
	}
	requested_bytes *= multiplier;
	if( requested_bytes == 0 )
		errx( "Error: Zero memory requested?\n" );
	u64_t mask = 0x80'00'00'00'00'00'00'00; // Leading 1 bit.
	u8_t garlic = 63;
	while( !(mask & requested_bytes) ) {
		mask >>= 1;
		--garlic;
	}
	return garlic;
}
u8_t dragonfly_parse_iterations (_RESTRICT (char const *) iter_c_str,
		                 _RESTRICT (char *)       temp,
				 int const                size)
{
	std::memcpy( temp, iter_c_str, (size + 1) );
	int num_digits = shift_left_digits( temp, size );
	if( num_digits > 3 || num_digits == 0 )
		errx( "Error: Invalid iteration count.\n" );
	int it = std::atoi( temp );
	if( it < 1 || it > 255 )
		errx( "Error: Invalid iteration count.\n" );
	return static_cast<u8_t>(it);
}
u64_t dragonfly_parse_padding (_RESTRICT (char const *) padding_c_str,
		               _RESTRICT (char *)       temp,
			       int const                size)
{
	std::memcpy( temp, padding_c_str, (size + 1) );
	u64_t multiplier = 1;
	for( int i = 0; i < size; ++i ) {
		switch( std::toupper( static_cast<unsigned char>(padding_c_str[ i ]) ) ) {
		case 'K':
			multiplier = Kibibyte;
			goto Have_Mul_L;
		case 'M':
			multiplier = Mebibyte;
			goto Have_Mul_L;
		case 'G':
			multiplier = Gibibyte;
			goto Have_Mul_L;
		}
	}
Have_Mul_L:
	int num_digits = shift_left_digits( temp, size );
	if( num_digits == 0 )
		errx( "Error: Asked for padding, without providing a number of padding bytes.\n" );
	static_assert (
		(std::is_same<u64_t,unsigned long int>::value ||
		std::is_same<u64_t,unsigned long long int>::value),
		"We require u64_t to be one of these."
	);
	u64_t pad;
	if constexpr (std::is_same<u64_t,unsigned long long int>::value) {
		pad = static_cast<u64_t>(std::strtoull( temp, nullptr, 10 ));
	} else if constexpr (std::is_same<u64_t,unsigned long int>::value) {
		pad = static_cast<u64_t>(std::strtoul( temp, nullptr, 10 ));
	}
	return pad * multiplier;
}
#endif/* ~ #ifdef __SSC_DRAGONFLY_V1__ */

static void set_mode (Threecrypt_Data &tc_data, Mode_E mode)
{
	if( tc_data.mode != Mode_E::None )
		errx( "%s\n%s\n", Mode_Already_Set, Help_Suggestion );
	tc_data.mode = mode;
}

static bool all_strings_are_consumed (char const **strings, int const count)
{
	for( int i = 0; i < count; ++i ) {
		if( strings[ i ] != nullptr )
			return false;
	}
	return true;
}

void threecrypt (int const argc, char const *argv[])
{
	Threecrypt_Data tc_data;
	tc_data.input_filename = nullptr;
	tc_data.output_filename = nullptr;
	tc_data.input_filename_size = 0;
	tc_data.output_filename_size = 0;
	tc_data.mode = Mode_E::None;

	C_Argument_Map c_arg_map{ argc, argv };
	char *temp = nullptr;
	process_io_arguments( tc_data, c_arg_map );
	process_mode_arguments( tc_data, c_arg_map );
	switch( tc_data.mode ) {
	default:
		{
			errx( "Error: Invalid, unrecognized mode (%d)\n%s",
			      static_cast<int>(tc_data.mode),
			      Help_Suggestion );
			break;
		}
	case( Mode_E::None ):
		{
			errx( "Error: No mode selected.\n%s",
			      Help_Suggestion );
			break;
		}
	case( Mode_E::Symmetric_Encrypt ):
		{
			if( tc_data.input_filename == nullptr )
				errx( "Error: No input filename was specified\n" );
			else if( tc_data.output_filename == nullptr ) {
				size_t const output_filename_size = tc_data.input_filename_size + sizeof(".3c"); // sizeof(".3c") includes a NULL terminator.
				temp = static_cast<char*>(std::malloc( output_filename_size ));
				if( temp == nullptr )
					errx( Generic_Error::Alloc_Failure );
				char *p = temp;
				std::memcpy( p, tc_data.input_filename, tc_data.input_filename_size );
				p += tc_data.input_filename_size;
				std::memcpy( p, ".3c", sizeof(".3c") );
				tc_data.output_filename = temp;
				tc_data.output_filename_size = output_filename_size;
			}
			/* Setup the input map. */
			_OPENBSD_UNVEIL (tc_data.input_filename, "r");   // Allow reading the input file.
			_OPENBSD_UNVEIL (tc_data.output_filename, "rwc");// Allow reading, writing, creating the output file.
			_OPENBSD_UNVEIL (nullptr,nullptr);               // Finalize unveil() calls.
			tc_data.input_map.os_file = open_existing_os_file( tc_data.input_filename, true );
			tc_data.input_map.size    = get_file_size( tc_data.input_map.os_file );
			map_file( tc_data.input_map, true );
			/* Setup the output map. */
			tc_data.output_map.os_file = create_os_file( tc_data.output_filename );
			/* Process the encrypt arguments. */
			process_encrypt_arguments( tc_data, c_arg_map );
			if( !all_strings_are_consumed( c_arg_map.c_strings, c_arg_map.count ) )
				errx( "Error: Unused, unecessary command-line arguments.\n" );
#if    defined (__SSC_DRAGONFLY_V1__)
			if( tc_data.input.g_low > tc_data.input.g_high )
				tc_data.input.g_high = tc_data.input.g_low;
			if( tc_data.input.lambda == 0 )
				tc_data.input.lambda = 1;
			dragonfly_v1::encrypt( tc_data.input,
					       tc_data.input_map,
					       tc_data.output_map,
					       tc_data.output_filename );
#elif  defined (__SSC_CBC_V2__)
			cbc_v2::encrypt( tc_data.input,
					 tc_data.input_map,
					 tc_data.output_map );
#else
#	error 'No supported crypto method'
#endif
			break;
		}
	case( Mode_E::Symmetric_Decrypt ):
		{
			if( !all_strings_are_consumed( c_arg_map.c_strings, c_arg_map.count ) )
				errx( "Error: Unused, unnecessary command-line arguments.\n" );
			else if( tc_data.input_filename == nullptr )
				errx( "Error: No input filename was specified\n" );
			else if( (tc_data.output_filename == nullptr) && (tc_data.input_filename_size >= 4)
			   && (std::strcmp( tc_data.input_filename + (tc_data.input_filename_size - 3), ".3c" ) == 0) )
			{
				size_t const size = tc_data.input_filename_size - 3;
				temp = static_cast<char*>(std::malloc( size + 1 ));
				if( temp == nullptr )
					errx( Generic_Error::Alloc_Failure );
				std::memcpy( temp, tc_data.input_filename, size );
				temp[ size ] = '\0';
				tc_data.output_filename = temp;
				tc_data.output_filename_size = size;
			}

			_OPENBSD_UNVEIL (tc_data.input_filename, "r");   // Allow reading the input file.
			_OPENBSD_UNVEIL (tc_data.output_filename, "rwc");// Allow reading, writing, creating the output file.
			_OPENBSD_UNVEIL (nullptr,nullptr);               // Finalize unveil() calls.
			tc_data.input_map.os_file = open_existing_os_file( tc_data.input_filename, true );
			tc_data.input_map.size    = get_file_size( tc_data.input_map.os_file );
			map_file( tc_data.input_map, true );
			Crypto_Method_E method = determine_crypto_method( tc_data.input_map );
			switch( method ) {
			default:
				{
					unmap_file( tc_data.input_map );
					close_os_file( tc_data.input_map.os_file );
					errx( "Error: Invalid decryption method %d\n", static_cast<int>(method) );
					break;
				}
			case( Crypto_Method_E::None ):
				{
					unmap_file( tc_data.input_map );
					close_os_file( tc_data.input_map.os_file );
					errx( "Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
					      tc_data.input_filename, Help_Suggestion );
					break;
				}
#ifdef __SSC_DRAGONFLY_V1__
			case( Crypto_Method_E::Dragonfly_V1 ):
				{
					tc_data.output_map.os_file = create_os_file( tc_data.output_filename );
					dragonfly_v1::decrypt( tc_data.input_map,
						               tc_data.output_map,
							       tc_data.output_filename );
					break;
				}
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				{
					tc_data.output_map.os_file = create_os_file( tc_data.output_filename );
					cbc_v2::decrypt( tc_data.input_map,
					                 tc_data.output_map,
							 tc_data.output_filename );
					break;
				}
#endif

			}
			break;
		}/*case( Mode_E::Symmetric_Encrypt )*/
	case( Mode_E::Dump_Fileheader ):
		{
			if( !all_strings_are_consumed( c_arg_map.c_strings, c_arg_map.count ) )
				errx( "Error: Unused, unnecessary command-line arguments.\n" );
			_OPENBSD_UNVEIL (tc_data.input_filename, "r");
			_OPENBSD_UNVEIL (nullptr,nullptr);
			_OPENBSD_PLEDGE ("stdio rpath tty",nullptr);
			tc_data.input_map.os_file = open_existing_os_file( tc_data.input_filename, true );
			tc_data.input_map.size    = get_file_size( tc_data.input_map.os_file );
			map_file( tc_data.input_map, true );
			
			Crypto_Method_E method = determine_crypto_method( tc_data.input_map );
			switch( method ) {
			default:
				{
					unmap_file( tc_data.input_map );
					close_os_file( tc_data.input_map.os_file );
					errx( "Error: Invalid decryption method (%d)\n", static_cast<int>(method) );
					break;
				}
			case( Crypto_Method_E::None ):
				{
					unmap_file( tc_data.input_map );
					close_os_file( tc_data.input_map.os_file );
					errx( "Error: The input file %s does not appear to be a valid 3crypt encrypted file.\n%s",
					      tc_data.input_filename, Help_Suggestion );
					break;
				}
#ifdef __SSC_DRAGONFLY_V1__
			case( Crypto_Method_E::Dragonfly_V1 ):
				{
					dragonfly_v1::dump_header( tc_data.input_map, tc_data.input_filename );
					break;
				}
#endif
#ifdef __SSC_CBC_V2__
			case( Crypto_Method_E::CBC_V2 ):
				{
					cbc_v2::dump_header( tc_data.input_map, tc_data.input_filename );
					break;
				}
#endif
			}/*switch( method */

			break;
		}/*case( Mode_E::Dump_Fileheader )*/
	}/*switch( tc_data.mode )*/
	std::free( temp );
}

#if 0
bool argument_cmp (C_Argument_Map           &c_arg_map,
		   int const                index,
		   _RESTRICT (char const *) c_str,
		   size_t const             size)
{
	if( c_arg_map.sizes[ index ] != size )
		return false;
	return std::strcmp( c_arg_map.c_strings[ index ], c_str ) == 0;
}

static inline bool next_string_is_valid (C_Argument_Map &c_arg_map, int const index)
{
	return ((index + 1) < c_arg_map.count) && (c_arg_map.c_strings[ index + 1 ]);
}
#endif

void process_io_arguments (Threecrypt_Data &tc_data, C_Argument_Map &c_arg_map)
{
	using std::strcmp;
	int const count = c_arg_map.count;
	_CTIME_CONST (auto&) Error_Too_Small = "Error: String %s is too small!\n";
	for( int i = 0; i < count; ++i ) {
		if( c_arg_map.c_strings[ i ] ) {
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-i"      ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--input" ) == 0 ) {
				if( ((i + 1) < count) && c_arg_map.c_strings[ i + 1 ] ) { // If there is another valid argument past this one
					c_arg_map.c_strings[ i ] = nullptr;
					//TODO Check file name sanity!!!
					tc_data.input_filename = c_arg_map.c_strings[ ++i ];
					c_arg_map.c_strings[ i ] = nullptr;
					continue;
				}
			} else
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-i"     , (sizeof("-i")      - 1) ) ||
			    argument_cmp( c_arg_map, i, "--input", (sizeof("--input") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-i"     , (sizeof("-i")      - 1) ) ||
			    c_arg_map.argument_cmp( i, "--input", (sizeof("--input") - 1) ) )
#endif
			{
				c_arg_map.c_strings[ i ] = nullptr;
#if 0
				if( next_string_is_valid( c_arg_map, i ) ) {
#else
				if( c_arg_map.next_string_is_valid( i ) ) {
#endif
					if( c_arg_map.sizes[ i ] < 1 )
						errx( Error_Too_Small, c_arg_map.c_strings[ i ] );
					tc_data.input_filename      = c_arg_map.c_strings[ ++i ];
					tc_data.input_filename_size = c_arg_map.sizes[ i ];
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#endif
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-o"       ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--output" ) == 0 ) {
				if( ((i + 1) < count) && c_arg_map.c_strings[ i + 1 ] ) {
					c_arg_map.c_strings[ i ] = nullptr;
					//TODO Check file name sanity!!!
					tc_data.output_filename = c_arg_map.c_strings[ ++i ];
					c_arg_map.c_strings[ i ] = nullptr;
					continue;
				}
			} else
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-o"      , (sizeof("-o")       - 1) ) ||
			    argument_cmp( c_arg_map, i, "--output", (sizeof("--output") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-o"      , (sizeof("-o")       - 1 ) ) ||
			    c_arg_map.argument_cmp( i, "--output", (sizeof("--output") - 1 ) ) )
#endif
			{
				c_arg_map.c_strings[ i ] = nullptr;
#if 0
				if( next_string_is_valid( c_arg_map, i ) ) {
#else
				if( c_arg_map.next_string_is_valid( i ) ) {
#endif
					if( c_arg_map.sizes[ i ] < 1 )
						errx( Error_Too_Small, c_arg_map.c_strings[ i ] );
					tc_data.output_filename = c_arg_map.c_strings[ ++i ];
					tc_data.output_filename_size = c_arg_map.sizes[ i ];
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#endif
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-h"     ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--help" ) == 0 ) {
				std::fputs( Help_Strings, stdout );
				std::exit( EXIT_SUCCESS );
			}
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-h"    , (sizeof("-h")     - 1) ) ||
			    argument_cmp( c_arg_map, i, "--help", (sizeof("--help") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-h"    , (sizeof("-h")     - 1 ) ) ||
			    c_arg_map.argument_cmp( i, "--help", (sizeof("--help") - 1 ) ) )
#endif
			{
				std::fputs( Help_String, stdout );
				std::exit( EXIT_SUCCESS );
			}
#endif
		}/* if( c_arg_map.c_strings[ i ] ) */
	}
}
void process_mode_arguments (Threecrypt_Data &tc_data, C_Argument_Map &c_arg_map)
{
	using std::strcmp;
	int const count = c_arg_map.count;
	for( int i = 0; i < count; ++i ) {
		if( c_arg_map.c_strings[ i ] ) {
#if 0
			if( argument_cmp( c_arg_map, i, "-e"       , (sizeof("-e")        - 1) ) ||
			    argument_cmp( c_arg_map, i, "--encrypt", (sizeof("--encrypt") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-e"       , (sizeof("-e")        - 1) ) ||
			    c_arg_map.argument_cmp( i, "--encrypt", (sizeof("--encrypt") - 1) ) )
#endif
			{
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E::Symmetric_Encrypt );
			} else
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-e"        ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--encrypt" ) == 0 ) {
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E:Symmetric_Encrypt );
				return;
			} else
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-d"       , (sizeof("-d")        - 1) ) ||
			    argument_cmp( c_arg_map, i, "--decrypt", (sizeof("--decrypt") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-d"       , sizeof("-d")        - 1 ) ||
			    c_arg_map.argument_cmp( i, "--decrypt", sizeof("--decrypt") - 1 ) )
#endif
			{
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E::Symmetric_Decrypt );
			} else
#endif
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-d"        ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--decrypt" ) == 0) {
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E::Symmetric_Decrypt );
				return;
			} else
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-D"    , (sizeof("-D")     - 1) ) ||
			    argument_cmp( c_arg_map, i, "--dump", (sizeof("--dump") - 1) ) )
#else
			if( c_arg_map.argument_cmp( i, "-D", (sizeof("-D") - 1) ) ||
			    c_arg_map.argument_cmp( i, "--dump", (sizeof("--dump") - 1) ) )
#endif
			{
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E::Dump_Fileheader );
			}
#endif
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-D"     ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--dump" ) == 0 ) {
				c_arg_map.c_strings[ i ] = nullptr;
				set_mode( tc_data, Mode_E::Dump_Fileheader );
				return;
			}
#endif
		}/* if( c_arg_map.c_strings[ i ] ) */
	}
}
void process_encrypt_arguments (Threecrypt_Data &tc_data, C_Argument_Map &c_arg_map)
{
	using std::strcmp;
	int const count = c_arg_map.count;
	char * const temp = static_cast<char*>(std::malloc( c_arg_map.max_string_size + 1 ));
	if( temp == nullptr )
		errx( Generic_Error::Alloc_Failure ); 
	tc_data.input.supplement_os_entropy = false;
#if    defined (__SSC_DRAGONFLY_V1__)
#	ifdef __3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC
			static_assert (std::is_same<decltype(__3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC),int>::value,
				       "The macro __3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC must be an integer!");
			static_assert (__3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC >  0);
			static_assert (__3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC < 63);
			_CTIME_CONST (u8_t) Default_Garlic = __3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC;
#	else
			_CTIME_CONST (u8_t) Default_Garlic = 23;
#	endif
			tc_data.input.padding_bytes = 0;
			tc_data.input.g_low = Default_Garlic;
			tc_data.input.g_high = Default_Garlic;
			tc_data.input.lambda = 1;
			tc_data.input.use_phi = 0;
#elif  defined (__SSC_CBC_V2__)
			tc_data.input.number_iterations     = 3'000'000;
			tc_data.input.number_concatenations = 3'000'000;
			_CTIME_CONST (int) Max_Chars = 10;
#else
#	error 'No Valid crypto method detected.'
#endif
	for( int i = 0; i < count; ++i ) {
		if( c_arg_map.c_strings[ i ] ) {
#if 0
			if( strcmp( c_arg_map.c_strings[ i ], "-E"        ) == 0 ||
			    strcmp( c_arg_map.c_strings[ i ], "--entropy" ) == 0 ) {
				c_arg_map.c_strings[ i ] = nullptr;
				tc_data.input.supplement_os_entropy = true;
				continue;
			} else
#else
#if 0
			if( argument_cmp( c_arg_map, i, "-E"       , (sizeof("-E")        - 1) ) ||
			    argument_cmp( c_arg_map, i, "--entropy", (sizeof("--entropy") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "-E"       , (sizeof("-E")        - 1) ) ||
			    c_arg_map.argument_cmp( i, "--entropy", (sizeof("--entropy") - 1) ) )
			{
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				tc_data.input.supplement_os_entropy = true;
			} else
#endif
#if    defined (__SSC_DRAGONFLY_V1__)
#	if 0
			if( strcmp( c_arg_map.c_strings[ i ], "--min-memory" ) == 0 ) {
			} else
#	else
#if 0
			if( argument_cmp( c_arg_map, i, "--min-memory", (sizeof("--min-memory") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--min-memory", (sizeof("--min-memory") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					tc_data.input.g_low = dragonfly_parse_memory( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#	endif
#if 0
			if( argument_cmp( c_arg_map, i, "--max-memory", (sizeof("--max-memory") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--max-memory", (sizeof("--max-memory") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
#if 0
				if( next_string_is_valid( c_arg_map, i ) ) {
#else
				if( c_arg_map.next_string_is_valid( i ) ) {
#endif
					++i;
					tc_data.input.g_high = dragonfly_parse_memory( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--use-memory", (sizeof("--use-memory") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--use-memory", (sizeof("--use-memory") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					tc_data.input.g_high = dragonfly_parse_memory( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					tc_data.input.g_low  = tc_data.input.g_high;
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--iterations", (sizeof("--iterations") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--iterations", (sizeof("--iterations") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					tc_data.input.lambda = dragonfly_parse_iterations( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--use-phi", (sizeof("--use-phi") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--use-phi", (sizeof("--use-phi") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				tc_data.input.use_phi = 1;
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--pad-by", (sizeof("--pad-by") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--pad-by", (sizeof("--pad-by") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					tc_data.input.padding_bytes = dragonfly_parse_padding( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					c_arg_map.c_strings[ i ] = nullptr;
				}
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--pad-to", (sizeof("--pad-to") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--pad-to", (sizeof("--pad-to") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					u64_t target = dragonfly_parse_padding( c_arg_map.c_strings[ i ], temp, c_arg_map.sizes[ i ] );
					c_arg_map.c_strings[ i ] = nullptr;
					if( target < dragonfly_v1::Visible_Metadata_Bytes ) {
						unmap_file( tc_data.input_map );
						close_os_file( tc_data.input_map.os_file );
						close_os_file( tc_data.output_map.os_file );
						remove( tc_data.output_filename );
						errx( "Error: The --pad-to target (%" PRIu64 ") is way too small!\n", target );
					}
					if( target - dragonfly_v1::Visible_Metadata_Bytes < tc_data.input_map.size ) {
						unmap_file( tc_data.input_map );
						close_os_file( tc_data.input_map.os_file );
						close_os_file( tc_data.output_map.os_file );
						remove( tc_data.output_filename );
						errx( "Error: The input map size (%" PRIu64 ") is too large to --pad-to %" PRIu64 "\n",
						      tc_data.input_map.size, target );
					} else {
						tc_data.input.padding_bytes = target;
						tc_data.input.padding_bytes -= tc_data.input_map.size;
						tc_data.input.padding_bytes -= dragonfly_v1::Visible_Metadata_Bytes;
					}
				}
			}
#elif  defined (__SSC_CBC_V2__)
#if 0
			if( argument_cmp( c_arg_map, i, "--iter-count", (sizeof("--iter-count") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--iter-count", (sizeof("--iter-count") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					size_t const size = c_arg_map.sizes[ i ];
					std::memcpy( temp, c_arg_map.c_strings[ i ], (size + 1) );
					c_arg_map.c_strings[ i ] = nullptr;
					int const num_digits = shift_left_digits( temp, size );
					if( num_digits > Max_Chars )
						errx( "Error: The specified sspkdf iteration count (%s) is too large.\n%s",
						      temp, Help_Suggestion );
					u32_t const num_iter = static_cast<u32_t>(std::atoi( temp ));
					if( num_iter == 0 )
						errx( "Error: Number sspkdf iterations specified is zero.\n" );
					tc_data.input.sspkdf_iterations = num_iter;
				}
			} else
#if 0
			if( argument_cmp( c_arg_map, i, "--concat-count", (sizeof("--concat-count") - 1) ) ) {
#else
			if( c_arg_map.argument_cmp( i, "--concat-count", (sizeof("--concat-count") - 1) ) ) {
#endif
				c_arg_map.c_strings[ i ] = nullptr;
				if( c_arg_map.next_string_is_valid( i ) ) {
					++i;
					size_t const size = c_arg_map.sizes[ i ];
					std::memcpy( temp, c_arg_map.c_strings[ i ], (size + 1) );
					c_arg_map.c_strings[ i ] = nullptr;
					int const num_digits = shift_left_digits( temp, size );
					if( num_digits > Max_Chars )
						errx( "Error: The specified sspkdf concatenatio count (%s) is too large.\n%s",
						      temp, Help_Suggestion );
					u32_t const num_concat = static_cast<u32_t>(std::atoi( temp ));
					if( num_concat == 0 )
						errx( "Error: Number sspkdf concatenations specified is zero.\n" );
					tc_data.input.sspkdf_concatenations = num_concat;
				}
			}
#else
#	error 'No valid crypto method detected.'
#endif
		}/* if( c_arg_map.c_strings[ i ] ) */
	}/* for( int i = 0; i < count; ++i ) */
	std::free( temp );
}
#if 0
void process_decrypt_arguments (Threecrypt_Data &tc_data, C_Argument_Map &c_arg_map)
{
	if( (tc_data.output_filename == nullptr) && (tc_data.input_filename_size >= 4)
	   && (std::strcmp( tc_data.input_filename + (tc_data.input_filename_size - 3),
			    ".3c" ) == 0) )
	{

	}
}
#endif
