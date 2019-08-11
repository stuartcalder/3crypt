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
    void CBC_V1_encrypt(char const * __restrict input_filename, char const * __restrict output_filename)
    {
        using namespace std;
        File_Data f_data;
        open_files( f_data, input_filename, output_filename );
#if   defined( __gnu_linux__ )
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#elif defined( _WIN64 )
        f_data.input_filesize = ssc::get_file_size( f_data.input_handle );
#else // All other platforms
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif

        f_data.output_filesize = calculate_CBC_V1_size( f_data.input_filesize );
#if   defined( __gnu_linux__ )
        set_file_size( f_data.output_fd, f_data.output_filesize );
#elif defined( _WIN64 )
        set_file_size( f_data.output_handle, f_data.output_filesize );
#else // All Other Platforms
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
                password_length = term.get_pw( password, Max_Password_Length, 1 );
                term.get_pw( pwcheck , Max_Password_Length, 1 );
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
    void CBC_V1_decrypt(char const * __restrict input_filename, char const * __restrict output_filename)
    {
        using namespace std;
        File_Data f_data;
        open_files( f_data, input_filename, output_filename );
#if   defined( __gnu_linux__ )
        f_data.input_filesize = ssc::get_file_size( f_data.input_fd );
#elif defined( _WIN64 )
        f_data.input_filesize = ssc::get_file_size( f_data.input_handle );
#else // All Other Platforms
        f_data.input_filesize = ssc::get_file_size( input_filename );
#endif
        f_data.output_filesize = f_data.input_filesize;
        /* The smallest a CBC_V1 encrypted file could ever be is one
         * CBC_V1-Header, one CBC-encrypted block, and one 512-bit
         * Message-Authentication-Code */
        static constexpr auto const Minimum_Possible_File_Size = sizeof(CBC_V1_Header_t) + Block_Bytes + MAC_Bytes;
        if ( f_data.input_filesize < Minimum_Possible_File_Size ) {
            fprintf( stderr, "Error: Input file doesn't appear to be large enough to be a %s encrypted file\n", CBC_V1_ID );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        // Set the size of the newly created output file to `f_data.output_fd`
#if   defined( __gnu_linux__ )
        set_file_size( f_data.output_fd, f_data.output_filesize );
#elif defined( _WIN64 )
        set_file_size( f_data.output_handle, f_data.output_filesize );
#else
        set_file_size( output_filename, f_data.output_filesize );
#endif
        map_files( f_data ); // Memory-Map the input and output files
        u8_t const * in = f_data.input_map;     // Get a pointer to the beginning of the input memory-map
        CBC_V1_Header_t header;                 // Declare a CBC_V1 header, to store the header from the input file                 
        memcpy( &header, in, sizeof(header) );  // Copy the header from the input file into 
        in += sizeof(header);                   // Increment the pointer by the size of the copied header
        static_assert(sizeof(header.id) == ssc::static_strlen(CBC_V1_ID)); // Ensure we know the sizes
        if ( memcmp( header.id, CBC_V1_ID, sizeof(header.id) ) != 0 )
        {// If the copied-in header isn't a CBC_V1 header ...
            // Cleanup & Die
            fprintf( stderr, "Error: The input file doesn't appear to be a `%s` encrypted file.\n", CBC_V1_ID );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        if ( header.total_size != static_cast<decltype(header.total_size)>(f_data.input_filesize) )
        {// If the size stored in the header doesn't match-up with the detected size of the input file...
            // Cleanup & Die
            fprintf( stderr, "Error: Input file size (%zu) does not equal the file size in the\n"
                             "file header of the input file (%zu).\n",
                             header.total_size, f_data.input_filesize );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        char password [Max_Password_Length] = { 0 }; // Declare a buffer, big enough for Max-Password_Length characters and a null
        int password_length;                         // Prepare to store the length of the password
        {
            ssc::Terminal term;                             // Create a ssc::Terminal abstraction
            password_length = term.get_pw( password, Max_Password_Length, 1 );// Copy terminally-input password into the password buffer
        }
        u8_t derived_key [Block_Bytes];         // Declare a buffer, big enough to store a 512-bit symmetric key
        /* Hash the password, with the random salt and compile-time iteration
           and concatenation constants */
        ssc::SSPKDF( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
        ssc::zero_sensitive( password, sizeof(password) ); // Securely zero over the entire password buffer
        {
            Skein_t skein;              // Declare a skein cryptographic Hash-Function object
            u8_t gen_mac [MAC_Bytes];   // Declare a 512-bit buffer, for storing the Message Authentication Code
            skein.MAC( gen_mac, f_data.input_map, derived_key,  // Generate a M.A.C. using the input file
                       f_data.input_filesize - MAC_Bytes, sizeof(derived_key), sizeof(gen_mac) );
            if ( memcmp( gen_mac, (f_data.input_map + f_data.input_filesize - MAC_Bytes), MAC_Bytes ) != 0 )
            {// If the stored message authentication code doesn't match the computed one...
                // Cleanup & Die
                fputs( "Error: Authentication failed.\n"
                       "Possibilities: wrong password, the file is corrupted, or it has been somehow tampered with.\n", stderr );
                ssc::zero_sensitive( derived_key, sizeof(derived_key) );
                unmap_files( f_data );
                close_files( f_data );
                remove( output_filename );
                exit( EXIT_FAILURE );
            }
        }
        size_t plaintext_size; // Prepare to store the size of the plaintext, in bytes
        {
            /* Create a CipherBlockChaining object using Threefish and the
             * derived key & cipher tweak. Prepare to decrypt.
             */
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            ssc::zero_sensitive( derived_key, sizeof(derived_key) ); // Securely zero over the derived key, now that we'v consumed it.
            /* All the metadata of a CBC_V1 encrypted file is in the header,
             * and the M.A.C. appended to the end of the file
             */
            static constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
            // Record the number of plaintext bytes during the decrypt
            plaintext_size = cbc.decrypt( in, f_data.output_map, f_data.input_filesize - File_Metadata_Size, header.cbc_iv );
        }
        sync_map( f_data ); // Synchronize all the bytes written to the Memory-Mapped output file
        unmap_files( f_data ); // Unmap the input and output files
        // Truncate the output file to the number of plaintext bytes
#if   defined( __gnu_linux__ )
        set_file_size( f_data.output_fd, plaintext_size );
#elif defined( _WIN64 )
        set_file_size( f_data.output_handle, plaintext_size );
#else   // All other operating systems
        set_file_size( output_filename, plaintext_size );
#endif
        close_files( f_data );
    }
} /* ! namespace threecrypt::cbc_v1 */
