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
    void CBC_V1_encrypt(Arg_Map_t const &opt_arg_pairs)
    {
        using namespace std;

        std::string input_filename, output_filename;
        if constexpr(Enable_Stdout) {
            puts( "Processing arguments..." );
        }
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
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Opening Files..." );
        }

        File_Data f_data;
        open_files( f_data, input_filename.c_str(), output_filename.c_str() );
#if defined(__gnu_linux__)
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename.c_str() );
#endif
        f_data.output_filesize = calculate_CBC_V1_size( f_data.input_filesize );
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename.c_str(), f_data.output_filesize );
#endif
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Memory-Mapping Files..." );
        }
        map_files( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Obtaining Passphrase..." );
        }
        char password [Max_Password_Length];
        int password_length;
        {
            ssc::Terminal term{ false, false, true };
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
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Generating Pseudo-Random Bytes for File Header..." );
        }
        ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
        ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
        header.num_iter   = 1'000'000;
        header.num_concat = 1'000'000;
        u8_t * out = f_data.output_map;
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Copying Header to File..." );
        }
        memcpy( out, &header, sizeof(header) );
        out += sizeof(header);
        u8_t derived_key [Block_Bytes];
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Deriving Encryption Key using SSPKDF..." );
        }
        ssc::SSPKDF( derived_key,
                     reinterpret_cast<char const *>(password),
                     password_length,
                     header.sspkdf_salt,
                     header.num_iter,
                     header.num_concat );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Securely Zeroing Password Buffer..." );
        }
        ssc::zero_sensitive( password, sizeof(password) );
        {
            if constexpr(Enable_Stdout) {
                printf( "...done\n"
                        "Encrypting '%s' into the file '%s' with Threefish-512 in CBC Mode...\n",
                        input_filename.c_str(), output_filename.c_str() );
            }
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            out += cbc.encrypt( f_data.input_map,
                                out,
                                f_data.input_filesize,
                                header.cbc_iv );
        }
        {
            if constexpr(Enable_Stdout) {
                puts( "...done\n"
                      "Generating Message Authentication Code..." );
            }
            Skein_t skein;
            skein.MAC( out,
                       f_data.output_map,
                       derived_key,
                       f_data.output_filesize - MAC_Bytes,
                       sizeof(derived_key),
                       MAC_Bytes );
        }
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Synchronizing Memory-Mapped Files..." );
        }
        sync_map( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Unmapping Memory-Mapped Files..." );
        }
        unmap_files( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Closing Files..." );
        }
        close_files( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Securely Zeroing Derived Key..." );
        }
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Successfully Encrypted using CBC_V1." );
        }
    }
    void CBC_V1_decrypt(Arg_Map_t const &opt_arg_pairs)
    {
        using namespace std;
        string input_filename, output_filename;
        if constexpr(Enable_Stdout) {
            puts( "Processing arguments..." );
        }
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
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Opening Files..." );
        }

        File_Data f_data;
        open_files( f_data, input_filename.c_str(), output_filename.c_str() );
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
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else // All other platforms
        set_file_size( output_filename.c_str(), f_data.output_filesize );
#endif
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Memory-Mapping Files..." );
        }
        map_files( f_data );
        u8_t const * in = f_data.input_map;
        CBC_V1_Header_t header;
        memcpy( &header, in, sizeof(header) );
        in += sizeof(header);
        static_assert(sizeof(header.id) == ssc::static_strlen(CBC_V1_ID));
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Processing File Header..." );
        }
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
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Obtaining Passphrase..." );
        }
        char password [Max_Password_Length] = { 0 };
        int password_length;
        {
            ssc::Terminal term{ false, false, true };
            term.get_pw( password, Max_Password_Length, 1 );
        }
        password_length = strlen( password );
        u8_t derived_key [Block_Bytes];
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Deriving Encryption Key using SSPKDF..." );
        }
        ssc::SSPKDF( derived_key,
                     reinterpret_cast<char const *>(password),
                     password_length,
                     header.sspkdf_salt,
                     header.num_iter,
                     header.num_concat );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Securely Zeroing Password Buffer..." );
        }
        ssc::zero_sensitive( password, sizeof(password) );
        {
            Skein_t skein;
            u8_t gen_mac [MAC_Bytes];
            if constexpr(Enable_Stdout) {
                puts( "...done\n"
                      "Generating Message Authentication Code..." );
            }
            skein.MAC( gen_mac,
                       f_data.input_map,
                       derived_key,
                       f_data.input_filesize - MAC_Bytes,
                       sizeof(derived_key),
                       sizeof(gen_mac) );
            if constexpr(Enable_Stdout) {
                printf( "...done\n"
                        "Comparing Message Authentication Code with the Header of '%s'...\n", input_filename.c_str() );
            }
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
            if constexpr(Enable_Stdout) {
                printf( "...done\n"
                        "Decrypting '%s' into the file '%s' with Threefish-512 in CBC Mode...",
                        input_filename.c_str(), output_filename.c_str() );
            }
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            plaintext_size = cbc.decrypt( in,
                                          f_data.output_map,
                                          f_data.input_filesize - (sizeof(CBC_V1_Header_t) + MAC_Bytes),
                                          header.cbc_iv );
        }
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Synchronizing Memory-Mapped Files..." );
        }
        sync_map( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Unammping Memory-Mapped Files..." );
        }
        unmap_files( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Closing files..." );
        }
#if defined(__gnu_linux__)
        set_file_size( f_data.output_fd, plaintext_size );
#else // All other platforms
        set_file_size( output_filename.c_str(), plaintext_size );
#endif
        close_files( f_data );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Securely Zeroing Derived Key..." );
        }
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
        if constexpr(Enable_Stdout) {
            puts( "...done\n"
                  "Successfully Decrypted using CBC_V1." );
        }
    }
} /* ! namespace threecrypt::cbc_v1 */
