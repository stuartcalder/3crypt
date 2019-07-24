#include "determine_decrypt_method.hh"

namespace threecrypt
{
    /* This function looks at the "magic bytes" at the beginning of a file,
     *  and tries to determine which 3crypt format it was encrypted with, if any.
     */
    Decryption_Method_e determine_decrypt_method(char const * filename)
    {
        // Get the size of the file.
        auto const file_size = ssc::get_file_size( filename );
        // Assume that the file is not a valid 3crypt encrypted file to start.
        auto method = Decryption_Method_e::None;

        // Discard files that are smaller than the smallest identifier string.
        if ( file_size < Smallest_Identifier_String_Size ) {
            std::fprintf( stderr, "Error: The file `%s` is too small to be a 3crypt encrypted file.\n", filename );
            std::exit( EXIT_FAILURE );
        }
        {
            // Open the file
            std::FILE * file_ptr;
            if ( (file_ptr = std::fopen( filename, "rb" )) == nullptr ) {
                std::fprintf( stderr, "Error: Failed to open `%s` to determine its decryption method.\n", filename );
                std::exit( EXIT_FAILURE );
            }
            // Create a buffer that can fit the biggest possible identifier string.
            u8_t buffer [Biggest_Identifier_String_Size];
            /* If the file is bigger than the biggest possible identifier string, read in Biggest_Identifier_String_Size bytes,
             * otherwise, read in the entire file to check it.
             */
            std::size_t const bytes_to_read = (file_size > Biggest_Identifier_String_Size) ? Biggest_Identifier_String_Size : file_size;
            std::size_t const read_bytes = std::fread( buffer, 1, bytes_to_read, file_ptr );
            // Ensure that all the requested bytes were read in.
            if ( read_bytes != bytes_to_read ) {
                std::fprintf( stderr, "Error: Failed to read bytes to determine decryption method: (%zu) requsted, (%zu) read.\n",
                              bytes_to_read, read_bytes );
                std::exit( EXIT_FAILURE );
            }
// If the CBC_V1 header was included, check to see if the file is a CBC_V1 encrypted file.
#ifdef CBC_V1_HH
            {
                using namespace cbc_v1;
                static_assert(sizeof(CBC_V1_Header_t::id) == ssc::static_strlen(CBC_V1_ID));
                if ( method == Decryption_Method_e::None &&
                     memcmp( buffer, CBC_V1_ID, sizeof(CBC_V1_Header_t::id) ) == 0 )
                {
                    method = Decryption_Method_e::CBC_V1;
                }
            }
#endif
// If the CBC_V2 header was included, check to see if the file is a CBC_V2 encrypted file.
#ifdef CBC_V2_HH
            {
                using namespace cbc_v2;
                static_assert(sizeof(CBC_V2_Header_t::id) == sizeof(CBC_V2_ID));
                if ( method == Decryption_Method_e::None &&
                     memcmp( buffer, CBC_V2_ID, sizeof(CBC_V2_Header_t::id) ) == 0 )
                {
                    method = Decryption_Method_e::CBC_V2;
                }
            }
#endif
            // Close the file.
            if ( std::fclose( file_ptr ) != 0 ) {
                std::fprintf( stderr, "Error: Failed to close `%s` after checking for its decryption method.\n", filename );
                std::exit( EXIT_FAILURE );
            }
        }
        // Return the detected needed decryption method.
        return method;
    }
} /* ! namespace threecrypt */
