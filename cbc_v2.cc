#include "cbc_v2.hh"

namespace threecrypt::cbc_v2
{

    static size_t calculate_CBC_V2_size(u64_t const pre_encryption_size)
    {
        /* CBC_V2 encrypted files */
        constexpr auto const File_Metadata_Size = CBC_V2_Header_t::Total_Size + MAC_Bytes;
        auto s = pre_encryption_size;
        if ( s < Block_Bytes )
            s = Block_Bytes;
        else
            s += ( Block_Bytes - (s % Block_Bytes) );
        return s + File_Metadata_Size;
    }
    void CBC_V2_encrypt(char const * input_filename,
                        char const * output_filename)
    {
        using namespace std;
        File_Data f_data;
        // Open files
        open_files( f_data, input_filename, output_filename );
        // Determine input file size
#ifdef __gnu_linux__
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif
        // Determine output file size
        f_data.output_filesize = calculate_CBC_V2_size( f_data.input_filesize );
        // Extend or shrink the output file to be `f_data.output_filesize` bytes
#ifdef __gnu_linux__
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else
        set_file_size( output_filename, f_data.output_filesize );
#endif
        // Memory-Map the files
        map_files( f_data );
        // Get the password
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
                    term.notify( "Passwords don't match.\n" );
            } while ( repeat );
            ssc::zero_sensitive( pwcheck, sizeof(pwcheck) );
        }
        // Create a header
        CBC_V2_Header_t header;
        static_assert(sizeof(header.id) == sizeof(CBC_V2_ID));
        memcpy( header.id, CBC_V2_ID, sizeof(header.id) );
        header.total_size = static_cast<decltype(header.total_size)>(f_data.output_filesize);
        ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
        ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
        header.num_iter   = 1'000'000;
        header.num_concat = 1'000'000;
        // Copy header into the file, field at a time, advancing the pointer
        u8_t * out = f_data.output_map;
        {
            memcpy( out, header.id, sizeof(header.id) );
            out += sizeof(header.id);
            *(reinterpret_cast<decltype(header.total_size) *>(out)) = header.total_size;
            out += sizeof(header.total_size);
            memcpy( out, header.tweak, sizeof(header.tweak) );
            out += sizeof(header.tweak);
            memcpy( out, header.sspkdf_salt, sizeof(header.sspkdf_salt) );
            out += sizeof(header.sspkdf_salt);
            memcpy( out, header.cbc_iv, sizeof(header.cbc_iv) );
            out += sizeof(header.cbc_iv);
            *(reinterpret_cast<decltype(header.num_iter) *>(out)) = header.num_iter;
            out += sizeof(header.num_iter);
            *(reinterpret_cast<decltype(header.num_concat) *>(out)) = header.num_concat;
            out += sizeof(header.num_concat);
        }

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
    void CBC_V2_decrypt(char const * input_filename,
                        char const * output_filename)
    {
        using namespace std;
        File_Data f_data;
        open_files( f_data, input_filename, output_filename );
#ifdef __gnu_linux__
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#else
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif
        f_data.output_filesize = f_data.input_filesize;
        static constexpr auto const Minimum_Possible_File_Size = CBC_V2_Header_t::Total_Size + Block_Bytes + MAC_Bytes;
        if ( f_data.input_filesize < Minimum_Possible_File_Size ) {
            fprintf( stderr, "Error: Input file doesn't appear to be large enough to be a %s encrypted file\n", CBC_V2_ID );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
#ifdef __gnu_linux__
        set_file_size( f_data.output_fd, f_data.output_filesize );
#else
        set_file_size( output_filename, f_data.output_filesize );
#endif
        map_files( f_data );
        u8_t const * in = f_data.input_map;
        CBC_V2_Header_t header;
        /* Copy all the fields of CBC_V2_Header_t from the memory-mapped file
           into the header struct */
        {
            memcpy( header.id         , in, sizeof(header.id)          );
            in += sizeof(header.id);
            memcpy( &header.total_size , in, sizeof(header.total_size)  );
            in += sizeof(header.total_size);
            memcpy( header.tweak      , in, sizeof(header.tweak)       );
            in += sizeof(header.tweak);
            memcpy( header.sspkdf_salt, in, sizeof(header.sspkdf_salt) );
            in += sizeof(header.sspkdf_salt);
            memcpy( header.cbc_iv     , in, sizeof(header.cbc_iv)      );
            in += sizeof(header.cbc_iv);
            memcpy( &header.num_iter   , in, sizeof(header.num_iter)    );
            in += sizeof(header.num_iter);
            memcpy( &header.num_concat , in, sizeof(header.num_concat)  );
            in += sizeof(header.num_concat);
        }
        static_assert(sizeof(header.id) == sizeof(CBC_V2_ID));
        if ( memcmp( header.id, CBC_V2_ID, sizeof(CBC_V2_ID) ) != 0 ) {
            fprintf( stderr, "Error: The input file doesn't appear to be a %s encrypted file.\n", CBC_V2_ID );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        if ( header.total_size != static_cast<decltype(header.total_size)>(f_data.input_filesize) ) {
            fprintf( stderr, "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
                     header.total_size, f_data.input_filesize );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        char password [Max_Password_Length] = { 0 };
        {
            ssc::Terminal term;
            term.get_pw( password, Max_Password_Length, 1 );
        }
        int password_length = strlen( password );
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key,
                     password,
                     password_length,
                     header.sspkdf_salt,
                     header.num_iter,
                     header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) );
        {
            u8_t gen_mac [MAC_Bytes];
            {
                Skein_t skein;
                skein.MAC( gen_mac,
                           f_data.input_map,
                           derived_key,
                           f_data.input_filesize - MAC_Bytes,
                           sizeof(derived_key),
                           sizeof(gen_mac) );
            }
            if ( memcmp( gen_mac, (f_data.input_map + f_data.input_filesize - MAC_Bytes), MAC_Bytes ) != 0 ) {
                fputs( "Error: Authentication failed.\n"
                       "Possibilities: Wrong password, the file is corrupted, or it has been somehow tampered with.", stderr );
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
            static constexpr auto const File_Metadata_Size = CBC_V2_Header_t::Total_Size + MAC_Bytes;
            plaintext_size = cbc.decrypt( in,
                                          f_data.output_map,
                                          f_data.input_filesize - File_Metadata_Size,
                                          header.cbc_iv );
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
