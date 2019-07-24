#include "3crypt.hh"
#include "cbc_v1.hh"
#include "cbc_v2.hh"
#include "determine_decrypt_method.hh"

#include <string>
#include <utility>

enum class Mode_e
{
    None,
    Symmetric_Encrypt,
    Symmetric_Decrypt
};

using Arg_Map_t = typename ssc::Arg_Mapping::Arg_Map_t;
using threecrypt::Help_String, threecrypt::Help_Suggestion;

static Arg_Map_t process_mode_args(Arg_Map_t && in_map, Mode_e & mode)
{
    Arg_Map_t extraneous_args;

    for ( int i = 1; i < in_map.size(); ++i ) {
        if ( in_map[ i ].first == "-h" ||
             in_map[ i ].first == "--help" )
        {
            std::puts( Help_String );
            std::exit( EXIT_SUCCESS );
        }
        else if ( in_map[ i ].first == "-e" ||
                  in_map[ i ].first == "--encrypt" )
        {
            if ( mode != Mode_e::None ) {
                std::fputs( "Error: Program mode already set.\n"
                            "(Only one mode switch (e.g -e or -d) is allowed per invocation of 3crypt.", stderr );
                std::fputs( Help_Suggestion, stderr );
                std::exit( EXIT_FAILURE );
            }
            mode = Mode_e::Symmetric_Encrypt;
        }
        else if ( in_map[ i ].first == "-d" ||
                  in_map[ i ].first == "--decrypt" )
        {
            if ( mode != Mode_e::None ) {
                std::fputs( "Error: Program mode already set.\n"
                            "(Only one mode switch( e.g. -e or -d) is allowed per invocation of 3crypt.", stderr );
                std::fputs( Help_Suggestion, stderr );
                std::exit( EXIT_FAILURE );
            }
            mode = Mode_e::Symmetric_Decrypt;
        }
        else if ( in_map[ i ].first.empty() &&
                  !(in_map[ i ].second.empty()) )
        {
            std::fprintf( stderr, "Error: floating arguments ( %s ) not allowed.\n", in_map[ i ].second.c_str() );
            std::fputs( Help_Suggestion, stderr );
            std::exit( EXIT_FAILURE );
        }
        else
        {
            extraneous_args.push_back( std::move( in_map[ i ] ) );
        }
    }
    return extraneous_args;
}

static Arg_Map_t process_encrypt_arguments(Arg_Map_t && opt_arg_pairs,
                                           std::string & input_filename,
                                           std::string & output_filename)
{
    using namespace std;

    Arg_Map_t extraneous_args;

    input_filename.clear();
    output_filename.clear();

    for ( auto && pair : opt_arg_pairs ) {
        ssc::check_file_name_sanity( pair.second, 1 );
        if ( pair.first == "-i" ||
             pair.first == "--input-file" )
        {
            input_filename = pair.second;
            if ( output_filename.empty() )
                output_filename = input_filename + ".3c";

        }
        else if ( pair.first == "-o" ||
                  pair.first == "--output-file" )
        {
            output_filename = pair.second;
        }
        else
        {
            extraneous_args.push_back( std::move( pair ) );
        }
    }
    if ( input_filename.empty() ) {
        fputs( "Error: The input filename has a length of zero.", stderr );
        exit( EXIT_FAILURE );
    }
    if ( output_filename.empty() ) {
        fputs( "Error: The output filename has a length of zero.", stderr );
        exit( EXIT_FAILURE );
    }
    return extraneous_args;
}

static Arg_Map_t process_decrypt_arguments(Arg_Map_t && opt_arg_pairs,
                                           std::string & input_filename,
                                           std::string & output_filename)
{
    using namespace std;

    Arg_Map_t extraneous_args;

    input_filename.clear();
    output_filename.clear();

    for ( auto && pair : opt_arg_pairs ) {
        ssc::check_file_name_sanity( pair.second, 1 );
        if ( pair.first == "-i" ||
             pair.first == "--input-file" )
        {
            input_filename = pair.second;
            if ( output_filename.empty() &&
                 input_filename.size() >= 3 &&
                 input_filename.substr( input_filename.size() - 3 ) == ".3c" )
            {
                output_filename = input_filename.substr( 0, input_filename.size() - 3 );
            }
        }
        else if ( pair.first == "-o" ||
                  pair.first == "--output-file" )
        {
            output_filename = pair.second;
        }
        else
        {
            extraneous_args.push_back( std::move( pair ) );
        }
    }
    if ( input_filename.empty() ) {
        fputs( "Error: The input filename has a length of zero.", stderr );
        exit( EXIT_FAILURE );
    }
    if ( output_filename.empty() ) {
        fputs( "Error: The output filename has a length of zero.", stderr );
        exit( EXIT_FAILURE );
    }
    return extraneous_args;
}

int main(int const argc, char const * argv[])
{
    using threecrypt::Decryption_Method_e;

    auto mode = Mode_e::None;
    std::string input_filename, output_filename;
    ssc::Arg_Mapping args{ argc, argv };
    auto mode_specific_arguments = process_mode_args( args.consume(), mode );
    switch ( mode ) {
        default:
        case (Mode_e::None):
            std::fprintf( stderr, "Error: No mode selected, or invalid mode: ( %d ) \n", static_cast<int>(mode) );
            std::exit( EXIT_FAILURE );
        case (Mode_e::Symmetric_Encrypt):
            {
                auto const remaining_args = process_encrypt_arguments( std::move( mode_specific_arguments ),
                                                                       input_filename, output_filename );
                if ( !remaining_args.empty() ) {
                    std::fprintf( stderr, "Error: Unneeded options or arguments: " );
                    for ( auto const & pair : remaining_args ) {
                        std::fprintf( stderr, "%s -> %s, ",
                                      pair.first.c_str(), pair.second.c_str() );
                    }
                    std::fputc( '\n', stderr );
                }
            }
            threecrypt::cbc_v2::CBC_V2_encrypt( input_filename.c_str(), output_filename.c_str() );
            break;
        case (Mode_e::Symmetric_Decrypt):
            {
                auto const remaining_args = process_decrypt_arguments( std::move( mode_specific_arguments ),
                                                                       input_filename, output_filename );
                if ( !remaining_args.empty() ) {
                    std::fprintf( stderr, "Error: Unneeded options or arguments: " );
                    for ( auto const & pair : remaining_args ) {
                        std::fprintf( stderr, "%s -> %s, ",
                                      pair.first.c_str(), pair.second.c_str() );
                    }
                    std::fputc( '\n', stderr );
                }
            }
            auto const method = threecrypt::determine_decrypt_method( input_filename.c_str() );
            switch ( method ) {
                default:
                    std::fprintf( stderr, "Error: Invalid decrypt method ( %d ).\n", static_cast<int>(method) );
                    std::exit( EXIT_FAILURE );
                case ( Decryption_Method_e::None ):
                    std::fprintf( stderr, "Error: the input file `%s` does not appear to be a valid 3crypt encrypted file.\n",
                                  input_filename.c_str() );
                    std::exit( EXIT_FAILURE );
#ifdef CBC_V1_HH
                case ( Decryption_Method_e::CBC_V1 ):
                    threecrypt::cbc_v1::CBC_V1_decrypt( input_filename.c_str(), output_filename.c_str() );
                    break;
#endif
#ifdef CBC_V2_HH
                case ( Decryption_Method_e::CBC_V2 ):
                    threecrypt::cbc_v2::CBC_V2_decrypt( input_filename.c_str(), output_filename.c_str() );
                    break;
#endif
            }
            break;
    } /* ! switch ( mode ) */

    return EXIT_SUCCESS;
}
