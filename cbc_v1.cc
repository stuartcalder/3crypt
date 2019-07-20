#include "cbc_v1.hh"

namespace threecrypt::cbc_v1
{

    static size_t calculate_CBC_V1_size(size_t pre_encryption_size)
    {
        constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
        auto s = pre_encryption_size;
        if ( s < Block_Bytes )
            s = Block_Bytes;
        else
            s += ( Block_Bytes - (s % Block_Bytes) );
        return s + File_Metadata_Size;
    }
#if 0
    void CBC_V1_encrypt(Arg_Map_t const &opt_arg_pairs)
    {
        using namespace std;

        std::string input_filename, output_filename;
        for ( auto const & pair : opt_arg_pairs ) {
            ssc::check_file_name_sanity( pair.second, 1 );
            if ( pair.first == "-i" ||
                 pair.first == "--input-file" )
            {
                input_filename = pair.second;
                if ( output_filename.size() == 0 )
                    output_filename = input_filename + ".3c";
            }
            else if ( pair.first == "-o" ||
                      pair.first == "--output-file" )
            {
                output_filename = pair.second;
            }
            else
            {
                fprintf( stderr, "Error: unrecongnizable switch %s\n", pair.first.c_str() );
                print_help();
                exit( EXIT_FAILURE );
            }
        }
        if ( input_filename.size() == 0 ||
             output_filename.size() == 0 )
        {
            fprintf( stderr, "Error: Either the input filename or the output filename has a length of zero.\n" );
            print_help();
            exit( EXIT_FAILURE );
        }

        File_Data f_data;
        open_files( f_data, input_filename.c_str(), output_filename.c_str() );
        // Determine input file size.
#if defined(__gnu_linux__)
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename.c_str() );
#endif
        f_data.output_filesize = calculate_CBC_V1_size( f_data.input_filesize );
        // Extend or shrink the output file to be `f_data.output_filesize` bytes.
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename.c_str(), f_data.output_filesize );
#endif
        map_files( f_data );
        char password [Max_Password_Length];
        int password_length;
        {
            ssc::Terminal term;
            char pwcheck [Max_Password_Length];
            bool repeat = true;
            do {
                static_assert(sizeof(password) == sizeof(pwcheck));
                memset( password, 0, sizeof(password) );
                memset( pwcheck , 0, sizeof(pwcheck) );
                term.get_pw( password, Max_Password_Length, 1 );
                term.get_pw( pwcheck , Max_Password_Length, 1 );
                password_length = strlen( password );
                if ( memcmp( password, pwcheck, sizeof(password) ) == 0 )
                    repeat = false;
                else
                    term.notify( "Passwords do not match.\n" );
            } while ( repeat );
            ssc::zero_sensitive( pwcheck, sizeof(pwcheck) );
        }
        CBC_V1_Header_t header;
        memcpy( header.id, CBC_V1_ID, sizeof(header.id) );
        header.total_size = static_cast<decltype(header.total_size)>(f_data.output_filesize);
        ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
        ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
        header.num_iter   = 1'000'000;
        header.num_concat = 1'000'000;
        u8_t * out = f_data.output_map;
        memcpy( out, &header, sizeof(header) );
        out += sizeof(header);
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key,
                     password,
                     password_length,
                     header.sspkdf_salt,
                     header.num_iter,
                     header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) );
        {
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            out += cbc.encrypt( f_data.input_map,
                                out,
                                f_data.input_filesize,
                                header.cbc_iv );
        }
        {
            Skein_t skein;
            skein.MAC( out,
                       f_data.output_map,
                       derived_key,
                       f_data.output_filesize - MAC_Bytes,
                       sizeof(derived_key),
                       MAC_Bytes );
        }
        sync_map( f_data );
        unmap_files( f_data );
        close_files( f_data );
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
    }
#endif
    void CBC_V1_encrypt(char const * input_filename, char const * output_filename)
    {
        using namespace std;
        File_Data f_data;
        open_files( f_data, input_filename, output_filename );
#ifdef __gnu_linux__
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif
        f_data.output_filesize = calculate_CBC_V1_size( f_data.input_filesize );
#ifdef __gnu_linux__
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename, f_data.output_filesize );
#endif
        map_files( f_data );
        char password [Max_Password_Length];
        int password_length;
        {
            ssc::Terminal term;
            char pwcheck [Max_Password_Length];
            bool repeat = true;
            do {
                static_assert(sizeof(password) == sizeof(pwcheck));
                memset( password, 0, sizeof(password) );
                memset( pwcheck , 0, sizeof(pwcheck)  );
                term.get_pw( password, Max_Password_Length, 1 );
                term.get_pw( pwcheck , Max_Password_Length, 1 );
                password_length = strlen( password );
                if ( memcmp( password, pwcheck, sizeof(password) ) == 0 )
                    repeat = false;
                else
                    term.notify( "Passwords do not match.\n" );
            } while ( repeat );
            ssc::zero_sensitive( pwcheck, sizeof(pwcheck) );
        }
        CBC_V1_Header_t header;
        memcpy( header.id, CBC_V1_ID, sizeof(header.id) );
        header.total_size = static_cast<decltype(header.total_size)>(f_data.output_filesize);
        ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
        ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
        header.num_iter = 1'000'000;
        header.num_concat = 1'000'000;
        u8_t * out = f_data.output_map;
        memcpy( out, &header, sizeof(header) );
        out += sizeof(header);
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) );
        {
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            out += cbc.encrypt( f_data.input_map, out, f_data.input_filesize, header.cbc_iv );
        }
        {
            Skein_t skein;
            skein.MAC( out, f_data.output_map, derived_key, f_data.output_filesize - MAC_Bytes, sizeof(derived_key), MAC_Bytes );
        }
        sync_map( f_data );
        unmap_files( f_data );
        close_files( f_data );
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
    }
#if 0
    void CBC_V1_decrypt(Arg_Map_t const &opt_arg_pairs)
    {
        using namespace std;
        string input_filename, output_filename;
        for ( auto const & pair : opt_arg_pairs ) {
            ssc::check_file_name_sanity( pair.second, 1 );
            if ( pair.first == "-i" ||
                 pair.first == "--input-file" )
            {
                input_filename = pair.second;
                if ( output_filename.size() == 0 &&
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
                fprintf( stderr, "Error: unrecognizable switch %s\n", pair.first.c_str() );
                print_help();
                exit( EXIT_FAILURE );
            }
        }
        if ( input_filename.size() == 0 ||
             output_filename.size() == 0 )
        {
            fprintf( stderr, "Error: Either the input filename or the output filename has a length of zero.\n"
                             "Ensure that both an input file and output file have been specified.\n" );
            print_help();
            exit( EXIT_FAILURE );
        }

        File_Data f_data;
        open_files( f_data, input_filename.c_str(), output_filename.c_str() );
        // Get the size of the input file in bytes.
#if defined(__gnu_linux__)
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename.c_str() );
#endif
        f_data.output_filesize = f_data.input_filesize;
        static constexpr auto const Minimum_Possible_File_Size = (sizeof(CBC_V1_Header_t) + Block_Bytes + MAC_Bytes);
        if ( f_data.input_filesize < Minimum_Possible_File_Size ) {
            fprintf( stderr, "Error: Input file doesn't appear to be large enough to be a %s encrypted file\n", CBC_V1_ID );
            close_files( f_data );
            remove( output_filename.c_str() );
            exit( EXIT_FAILURE );
        }
        // Set the size of the output file to `f_data.output_filesize` bytes.
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename.c_str(), f_data.output_filesize );
#endif
        map_files( f_data );
        u8_t const * in = f_data.input_map;
        CBC_V1_Header_t header;
        memcpy( &header, in, sizeof(header) );
        in += sizeof(header);
        static_assert(sizeof(header.id) == ssc::static_strlen(CBC_V1_ID));
        if ( memcmp( header.id, CBC_V1_ID, sizeof(header.id) ) != 0 ) {
            fprintf( stderr, "Error: The input file doesn't appear to be a %s encrypted file.\n", CBC_V1_ID );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename.c_str() );
            exit( EXIT_FAILURE );
        }
        if ( header.total_size != static_cast<decltype(header.total_size)>(f_data.input_filesize) ) {
            fprintf( stderr, "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
                     header.total_size, f_data.input_filesize );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename.c_str() );
            exit( EXIT_FAILURE );
        }
        char password [Max_Password_Length] = { 0 };
        int password_length;
        {
            ssc::Terminal term;
            term.get_pw( password, Max_Password_Length, 1 );
        }
        password_length = strlen( password );
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key,
                     password,
                     password_length,
                     header.sspkdf_salt,
                     header.num_iter,
                     header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) );
        {
            Skein_t skein;
            u8_t gen_mac [MAC_Bytes];
            skein.MAC( gen_mac,
                       f_data.input_map,
                       derived_key,
                       f_data.input_filesize - MAC_Bytes,
                       sizeof(derived_key),
                       sizeof(gen_mac) );
            if ( memcmp( gen_mac, (f_data.input_map + f_data.input_filesize - MAC_Bytes), MAC_Bytes ) != 0 ) {
                fprintf( stderr, "Error: Authentication failed.\n"
                                 "Possibilities: Wrong password, the file is corrupted, or it has been somehow tampered with.\n" );
                unmap_files( f_data );
                close_files( f_data );
                remove( output_filename.c_str() );
                ssc::zero_sensitive( derived_key, sizeof(derived_key) );
                exit( EXIT_FAILURE );
            }
        }
        size_t plaintext_size;
        {
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            static constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
            plaintext_size = cbc.decrypt( in,
                                          f_data.output_map,
                                          f_data.input_filesize - File_Metadata_Size,
                                          header.cbc_iv );
        }
        sync_map( f_data );
        unmap_files( f_data );
        // Shrink the output file to the size of the plaintext.
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, plaintext_size );
#else // All other platforms
        set_file_size( output_filename.c_str(), plaintext_size );
#endif
        close_files( f_data );
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
    }
#endif
    void CBC_V1_decrypt(char const * input_filename, char const * output_filename)
    {
        using namespace std;
        File_Data f_data;
        open_files( f_data, input_filename, output_filename );
#ifdef __gnu_linux__
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif
        f_data.output_filesize = f_data.input_filesize;
        static constexpr auto const Minimum_Possible_File_Size = sizeof(CBC_V1_Header_t) + Block_Bytes + MAC_Bytes;
        if ( f_data.input_filesize < Minimum_Possible_File_Size ) {
            fprintf( stderr, "Error: Input file doesn't appear to be large enough to be a %s encrypted file\n", CBC_V1_ID );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
#ifdef __gnu_linux__
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename, f_data.output_filesize );
#endif
        map_files( f_data );
        u8_t const * in = f_data.input_map;
        CBC_V1_Header_t header;
        memcpy( &header, in, sizeof(header) );
        in += sizeof(header);
        static_assert(sizeof(header.id) == ssc::static_strlen(CBC_V1_ID));
        if ( memcmp( header.id, CBC_V1_ID, sizeof(header.id) ) != 0 ) {
            fprintf( stderr, "Error: The input file doesn't appear to be a `%s` encrypted file.\n", CBC_V1_ID );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        if ( header.total_size != static_cast<decltype(header.total_size)>(f_data.input_filesize) ) {
            fprintf( stderr, "Error: Input file size (%zu) does not equal the file size in the\n"
                             "file header of the input file (%zu).\n",
                             header.total_size, f_data.input_filesize );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        char password [Max_Password_Length] = { 0 };
        int password_length;
        {
            ssc::Terminal term;
            term.get_pw( password, Max_Password_Length, 1 );
        }
        password_length = strlen( password );
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) );
        {
            Skein_t skein;
            u8_t gen_mac [MAC_Bytes];
            skein.MAC( gen_mac, f_data.input_map, derived_key,
                       f_data.input_filesize - MAC_Bytes, sizeof(derived_key), sizeof(gen_mac) );
            if ( memcmp( gen_mac, (f_data.input_map + f_data.input_filesize - MAC_Bytes), MAC_Bytes ) != 0 ) {
                fputs( "Error: Authentication failed.\n"
                       "Possibilities: wrong password, the file is corrupted, or it has been somehow tampered with.\n", stderr );
                unmap_files( f_data );
                close_files( f_data );
                remove( output_filename );
                ssc::zero_sensitive( derived_key, sizeof(derived_key) );
                exit( EXIT_FAILURE );
            }
        }
        size_t plaintext_size;
        {
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            static constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
            plaintext_size = cbc.decrypt( in, f_data.output_map, f_data.input_filesize - File_Metadata_Size, header.cbc_iv );
        }
        sync_map( f_data );
        unmap_files( f_data );
#ifdef __gnu_linux__
        set_file_size( f_data.output_fd, plaintext_size );
#else
        set_file_size( output_filename, plaintext_size );
#endif
        close_files( f_data );
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
    }
} /* ! namespace threecrypt::cbc_v1 */
