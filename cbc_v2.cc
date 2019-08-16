#include <cstdio>
#include "cbc_v2.hh"
#include "input_abstraction.hh"
#include <ssc/general/print.hh>

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
    void CBC_V2_encrypt(Input_Abstraction const & input_abstr)
    {
        using namespace std;
        File_Data f_data;
        // Open files
        open_files( f_data, input_abstr.input_filename.c_str(), input_abstr.output_filename.c_str() );
        // Determine input file size
#if   defined( __gnu_linux__ ) || defined( _WIN64 )
        f_data.input_map.size = ssc::get_file_size( f_data.input_map.os_file );
#else
        f_data.input_map.size = ssc::get_file_size( input_abstr.input_filename.c_str() );
#endif
        // Determine output file size
        f_data.output_map.size = calculate_CBC_V2_size( f_data.input_map.size );
        // Extend or shrink the output file to be `f_data.output_filesize` bytes
#if   defined( __gnu_linux__ ) || defined( _WIN64 )
        set_file_size( f_data.output_map.os_file, f_data.output_map.size );
#else
        set_file_size( input_abstr.output_filename.c_str(), f_data.output_map.size );
#endif
        // Memory-Map the files
        map_files( f_data );
        // Get the password
        char password [Max_Password_Length + 1];
        int password_length;
        {
            ssc::Terminal term;
            char pwcheck [Max_Password_Length + 1];
            bool repeat = true;
            do {
                static_assert(sizeof(password) == sizeof(pwcheck));
                memset( password, 0, sizeof(password) );
                memset( pwcheck , 0, sizeof(pwcheck) );
                password_length = term.get_pw( password, Max_Password_Length, 1 );
                term.get_pw( pwcheck , Max_Password_Length, 1 );
                if ( memcmp( password, pwcheck, sizeof(password) ) == 0 )
                    repeat = false;
                else
                    term.notify( "Passwords don't match." );
            } while ( repeat );
            ssc::zero_sensitive( pwcheck, sizeof(pwcheck) );
        }
        // Create a header
        CBC_V2_Header_t header;
        static_assert(sizeof(header.id) == sizeof(CBC_V2_ID));
        memcpy( header.id, CBC_V2_ID, sizeof(header.id) );
        header.total_size = static_cast<decltype(header.total_size)>(f_data.output_map.size);
        ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
        ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
        header.num_iter = input_abstr.number_iterations;
        header.num_concat = input_abstr.number_concatenations;
        // Copy header into the file, field at a time, advancing the pointer
        u8_t * out = f_data.output_map.ptr;
        {
            memcpy( out, header.id, sizeof(header.id) );
            out += sizeof(header.id);

            memcpy( out, &header.total_size, sizeof(header.total_size) );
            out += sizeof(header.total_size);

            memcpy( out, header.tweak, sizeof(header.tweak) );
            out += sizeof(header.tweak);

            memcpy( out, header.sspkdf_salt, sizeof(header.sspkdf_salt) );
            out += sizeof(header.sspkdf_salt);

            memcpy( out, header.cbc_iv, sizeof(header.cbc_iv) );
            out += sizeof(header.cbc_iv);

            memcpy( out, &header.num_iter, sizeof(header.num_iter) );
            out += sizeof(header.num_iter);

            memcpy( out, &header.num_concat, sizeof(header.num_concat) );
            out += sizeof(header.num_concat);
        }

        // Generate a 512-bit symmetric key using the password we got earlier as input
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
        // Securely zero over the password buffer after we've used it to generate the symmetric key
        ssc::zero_sensitive( password, sizeof(password) );
        {// Encrypt the input file, writing the ciphertext into the memory-mapped output file
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            out += cbc.encrypt( f_data.input_map.ptr, out, f_data.input_map.size, header.cbc_iv );
        }
        {/* Create a 512-bit Message Authentication Code of the ciphertext, using the derived key and the ciphertext with Skein's native MAC
            then append the MAC to the end of the ciphertext */
            Skein_t skein;
            skein.MAC( out, f_data.output_map.ptr, derived_key, f_data.output_map.size - MAC_Bytes, sizeof(derived_key), MAC_Bytes );
        }
        // Securely zero over the derived key
        ssc::zero_sensitive( derived_key, sizeof(derived_key) );
        // Synchronize everything written to the output file
        sync_map( f_data );
        // Unmap the input and output files
        unmap_files( f_data );
        // Close the input and output files
        close_files( f_data );
    }
    void CBC_V2_decrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename)
    {
        using namespace std;
        File_Data f_data;
        // Open the files
        open_files( f_data, input_filename, output_filename );
        // Get the size fo the input file
#if   defined( __gnu_linux__ ) || defined( _WIN64 )
        f_data.input_map.size = ssc::get_file_size( f_data.input_map.os_file );
#else
        f_data.input_map.size = ssc::get_file_size( input_filename );
#endif
        // For now, assume the size of the output file will be the same size as the input file
        f_data.output_map.size = f_data.input_map.size;
        // Check to see if the input file is too small to have possibly been 3crypt encrypted, using any supported means
        static constexpr auto const Minimum_Possible_File_Size = CBC_V2_Header_t::Total_Size + Block_Bytes + MAC_Bytes;
        if ( f_data.input_map.size < Minimum_Possible_File_Size )
        {
            fprintf( stderr, "Error: Input file doesn't appear to be large enough to be a %s encrypted file\n", CBC_V2_ID );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        // Set the output file to be `f_data.output_filesize` bytes
#if   defined( __gnu_linux__ ) || defined( _WIN64 )
        set_file_size( f_data.output_map.os_file, f_data.output_map.size );
#else
        set_file_size( output_filename, f_data.output_map.size );
#endif
        // Memory-map the input and output files
        map_files( f_data );
        // `in` pointer used for reading from the input files, and incremented as it's used to read
        u8_t const * in = f_data.input_map.ptr;
        CBC_V2_Header_t header;
        /* Copy all the fields of CBC_V2_Header_t from the memory-mapped file
           into the header struct */
        {
            memcpy( header.id, in, sizeof(header.id) );
            in += sizeof(header.id);

            memcpy( &header.total_size, in, sizeof(header.total_size) );
            in += sizeof(header.total_size);

            memcpy( header.tweak, in, sizeof(header.tweak) );
            in += sizeof(header.tweak);

            memcpy( header.sspkdf_salt, in, sizeof(header.sspkdf_salt) );
            in += sizeof(header.sspkdf_salt);

            memcpy( header.cbc_iv, in, sizeof(header.cbc_iv) );
            in += sizeof(header.cbc_iv);

            memcpy( &header.num_iter, in, sizeof(header.num_iter) );
            in += sizeof(header.num_iter);

            memcpy( &header.num_concat, in, sizeof(header.num_concat) );
            in += sizeof(header.num_concat);
        }
        // Check for the magic "3CRYPT_CBC_V2" at the beginning of the file header
        static_assert(sizeof(header.id) == sizeof(CBC_V2_ID));
        if ( memcmp( header.id, CBC_V2_ID, sizeof(CBC_V2_ID) ) != 0 )
        {
            fprintf( stderr, "Error: The input file doesn't appear to be a %s encrypted file.\n", CBC_V2_ID );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        // Check that the input file is the same size as specified by the file header
        if ( header.total_size != static_cast<decltype(header.total_size)>(f_data.input_map.size) )
        {
            fprintf( stderr, "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
                     header.total_size, f_data.input_map.size );
            unmap_files( f_data );
            close_files( f_data );
            remove( output_filename );
            exit( EXIT_FAILURE );
        }
        // Get the password
        char password [Max_Password_Length + 1] = { 0 };
        int password_length;
        {
            ssc::Terminal term;
            password_length = term.get_pw( password, Max_Password_Length, 1 );
        }
        // Generate a 512-bit symmetric key from the given password
        u8_t derived_key [Block_Bytes];
        ssc::SSPKDF( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
        // Securely zero over the password now that we have the derived key
        ssc::zero_sensitive( password, sizeof(password) );
        {
            // Generate a MAC using the ciphertext and the derived key, and compare it to the MAC at the end of the input file
            u8_t gen_mac [MAC_Bytes];
            {
                Skein_t skein;
                skein.MAC( gen_mac,
                           f_data.input_map.ptr,
                           derived_key,
                           f_data.input_map.size - MAC_Bytes,
                           sizeof(derived_key),
                           sizeof(gen_mac) );
            }
            if ( memcmp( gen_mac, (f_data.input_map.ptr + f_data.input_map.size - MAC_Bytes), MAC_Bytes ) != 0 )
            {
                ssc::zero_sensitive( derived_key, sizeof(derived_key) );
                fputs( "Error: Authentication failed.\n"
                       "Possibilities: Wrong password, the file is corrupted, or it has been somehow tampered with.\n", stderr );
                unmap_files( f_data );
                close_files( f_data );
                remove( output_filename );
                exit( EXIT_FAILURE );
            }
        }
        size_t plaintext_size;
        {
            // Decrypt the input file's ciphertext into the output file, recording the number of bytes of plaintext in `plaintext_size`
            CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
            // Securely zero over the derived key now that we're done with it
            ssc::zero_sensitive( derived_key, sizeof(derived_key) );
            static constexpr auto const File_Metadata_Size = CBC_V2_Header_t::Total_Size + MAC_Bytes;
            plaintext_size = cbc.decrypt( in,
                                          f_data.output_map.ptr,
                                          f_data.input_map.size - File_Metadata_Size,
                                          header.cbc_iv );
        }
        // Synchronize the output file
        synchronize_map( f_data.output_map );
        // Unmap the memory-mapped input and output files
        unmap_files( f_data );
        // Truncate the output file to the number of plaintext bytes
#if   defined( __gnu_linux__ ) || defined( _WIN64 )
        set_file_size( f_data.output_map.os_file, plaintext_size );
#else
        set_file_size( output_filename, plaintext_size );
#endif
        // Close the input and output files
        close_files( f_data );
    }
    void dump_header(char const * filename)
    {
        using std::memcpy, std::fprintf, std::fputs, std::putchar, std::exit;
        OS_Map os_map;
        os_map.os_file = open_file_existing( filename, true );
        os_map.size    = ssc::get_file_size( os_map.os_file );
        static constexpr auto const Minimum_Size = CBC_V2_Header_t::Total_Size + Block_Bytes + MAC_Bytes;
        if ( os_map.size < Minimum_Size )
        {
            close_file( os_map.os_file );
            fprintf( stderr, "File %s looks too small to be CBC_V2 encrypted\n", filename );
            exit( EXIT_FAILURE );
        }
        map_file( os_map, true );

        CBC_V2_Header_t header;
        u8_t mac [MAC_Bytes];
        {
            u8_t const * p = os_map.ptr;

            memcpy( header.id, p, sizeof(header.id) );
            p += sizeof(header.id);

            memcpy( &header.total_size, p, sizeof(header.total_size) );
            p += sizeof(header.total_size);

            memcpy( header.tweak, p, sizeof(header.tweak) );
            p += sizeof(header.tweak);

            memcpy( header.sspkdf_salt, p, sizeof(header.sspkdf_salt) );
            p += sizeof(header.sspkdf_salt);

            memcpy( header.cbc_iv, p, sizeof(header.cbc_iv) );
            p += sizeof(header.cbc_iv);

            memcpy( &header.num_iter, p, sizeof(header.num_iter) );
            p += sizeof(header.num_iter);

            memcpy( &header.num_concat, p, sizeof(header.num_concat) );

            p = os_map.ptr + os_map.size - MAC_Bytes;
            memcpy( mac, p, MAC_Bytes );
        }
        unmap_file( os_map );
        close_file( os_map.os_file );

        fprintf( stdout,   "File Header ID             : %s\n", header.id );
        fprintf( stdout,   "File Size                  : %zu\n", header.total_size );
        fputs  (           "Threefish Tweak            : ", stdout );
        ssc::print_integral_buffer<u8_t>( header.tweak, sizeof(header.tweak) );
        fputs  (         "\nSSPKDF Salt                : ", stdout );
        ssc::print_integral_buffer<u8_t>( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
        fputs  (         "\nCBC Initialization Vector  : ", stdout );
        ssc::print_integral_buffer<u8_t>( header.cbc_iv, sizeof(header.cbc_iv) );
        fprintf( stdout, "\nNumber Iterations          : %u\n", header.num_iter );
        fprintf( stdout,   "Number Concatenations      : %u\n", header.num_concat );
        fputs(             "Message Authentication Code: ", stdout );
        ssc::print_integral_buffer<u8_t>( mac, sizeof(mac) );
        std::putchar( '\n' );
    }
} /* ! namespace threecrypt::cbc_v1 */
