#include "3crypt.hh"
#include "cbc_v1.hh"

enum class Program_Mode_e {
    None,
    Symmetric_Encrypt,
    Symmetric_Decrypt
};
using Arg_Map_t = typename ssc::Arg_Mapping::Arg_Map_t;

static Arg_Map_t process_args(Arg_Map_t const &in_map, Program_Mode_e & mode)
{
    Arg_Map_t out_map;

    for ( int i = 1; i < in_map.size(); ++i ) {
        if ( in_map[ i ].first == "-h" ||
             in_map[ i ].first == "--help" )
        {
            threecrypt::print_help();
            std::exit( EXIT_SUCCESS );
        }
        else if ( in_map[ i ].first == "-e" ||
                  in_map[ i ].first == "--encrypt" )
        {
            if ( mode != Program_Mode_e::None ) {
                std::fprintf( stderr, "Error: Program mode already set.\n"
                                      "(Only one mode switch (e.g. -e or -d) is allowed per invocation of 3crypt.\n" );
                std::exit( EXIT_FAILURE );
            }
            else mode = Program_Mode_e::Symmetric_Encrypt;
        }
        else if ( in_map[ i ].first == "-d" ||
                  in_map[ i ].first == "--decrypt" )
        {
            if ( mode != Program_Mode_e::None ) {
                std::fprintf( stderr, "Error: Program mode already set.\n"
                                      "(Only one mode switch( e.g. -e or -d) is allowed per invocation of 3crypt.\n" );
                std::exit( EXIT_FAILURE );
            }
            else mode = Program_Mode_e::Symmetric_Decrypt;
        }
        else if ( in_map[ i ].first.size() == 0 &&
                  in_map[ i ].second.size() != 0 )
        {
            std::fprintf( stderr, "Error: floating arguments ( %s ) not allowed.\n", in_map[ i ].second.c_str() );
            std::exit( EXIT_FAILURE );
        }
        else
        {
            out_map.push_back( in_map[ i ] );
        }
    }
    return out_map;
}

int main(int const argc, char const * argv[])
{
    auto mode = Program_Mode_e::None;
    {
        ssc::Arg_Mapping args{ argc, argv };
        auto map = args.consume();
        auto specific_options = process_args( map, mode );
        switch ( mode ) {
            default:
            case (Program_Mode_e::None):
                std::fprintf( stderr, "Error: No mode selected, or invalid mode: ( %d ) \n", static_cast<int>(mode) );
                std::exit( EXIT_FAILURE );
            case (Program_Mode_e::Symmetric_Encrypt):
                threecrypt::cbc_v1::CBC_V1_encrypt( specific_options );
                break;
            case (Program_Mode_e::Symmetric_Decrypt):
                threecrypt::cbc_v1::CBC_V1_decrypt( specific_options );
                break;
        }
    }

    return EXIT_SUCCESS;
}
