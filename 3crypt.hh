#ifndef THREECRYPT_HH
#define THREECRYPT_HH
/* SSC Library Includes */
#include <ssc/general/arg_mapping.hh>   // Processing Command-Line Arguments
#include <ssc/general/static_string.hh> // Constexpr C-String Functionalities
#include <ssc/crypto/operations.hh>     // Genericized Cryptographic Operations
#include <ssc/crypto/threefish.hh>      // Threefish Tweakable Block Cipher
#include <ssc/crypto/cbc.hh>            // Cipher Block Chaining Mode for Threefish
#include <ssc/crypto/skein.hh>          // Skein hash function for its Message Authentication Code Functionality
#include <ssc/crypto/sspkdf.hh>         // SSPKDF Key-Derivation Function
#include <ssc/files/files.hh>           // Genericized File-Related Functions
#include <ssc/interface/terminal.hh>    // Terminal Interface
#include <ssc/general/integers.hh>      // Integer Type Aliases
/* Platform-Specific Includes */
#if   defined(__gnu_linux__)
    #include <sys/types.h> // For Some Types That We Need
    #include <sys/stat.h>  // The stat() Family of Functions
    #include <fcntl.h>     // File Control Options
    #include <sys/mman.h>  // Memory-Mapping Related Functions and Defines
    #include <unistd.h>    // ftruncate() and truncate() Etc. 
#elif defined(_WIN64)
    #include <windows.h>    // Windows Functions, Macros, Etc.
    #include <memoryapi.h>  // Windows Memory-Mapping API
#else
    #error "Currently, only Gnu/Linux and 64-bit MS Windows are implemented."
#endif
/* Standard Library Includes */
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace threecrypt
{
    static_assert(CHAR_BIT == 8);
    static constexpr auto const Salt_Bits   = 128;             // Sufficiently-Big 128-Bit Salt for SSPKDF.
    static constexpr auto const Salt_Bytes  = Salt_Bits / 8;   // Number of SSPKDF Salt Bytes.
    static constexpr auto const Tweak_Bits  = 128;             // Required 128-Bit Tweak for Threefish.
    static constexpr auto const Tweak_Bytes = Tweak_Bits / 8;  // Number of Threefish Tweak Bytes.
    static constexpr auto const Block_Bits  = 512;             // Use the 512-Bit Block Variants for Algorithms Here.
    static constexpr auto const Block_Bytes = Block_Bits / 8;  // Number of Bytes in One Cipher-Block-Chain'd Block; Bytes of State.
    static constexpr auto const MAC_Bytes   = Block_Bytes;     /* Use the same number of bytes of Message Authentication Code
                                                                  as is in the block. */
    static constexpr auto const   Max_Password_Length = 120;   // 80 as The Longest Legal Password, Arbitrarily.
    static constexpr auto const & Help_String = "Usage: 3crypt [Mode] [Switch...]\n"
                                                "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; NOT 3crypt -e -ifile)\n"
                                                "Modes:\n"
                                                "-e, --encrypt  Symmetric encryption mode; encrypt a file using a passphrase.\n"
                                                "-d, --decrypt  Symmetric decryption mode; decrypt a file using a passphrase.\n"
                                                "Switches:\n"
                                                "-i, --input-file  Input file ; Must be specified for symmetric encryption and decryption modes.\n"
                                                "-o, --output-file Output file; For symmetric encryption and decryption modes. Optional for encryption.";
    static constexpr auto const & Help_Suggestion = "( Use 3crypt --help for more information )\n";

    // Abstractly Define Cryptographic Primitives
    using Threefish_t = ssc::Threefish<Block_Bits>;             // Use Threefish<Block_Bits> as Default Block-Cipher in 3crypt.
    using Skein_t     = ssc::Skein    <Block_Bits>;             // Use Skein<Block_Bits> as Default Cryptographic Hash-Function in 3crypt.
    using CBC_t       = ssc::CBC<Threefish_t, Block_Bits>;      // Use Threefish Block Cipher in Cipher-Block-Chaining Mode.
    // Abstractly Define Standard Types
    using Arg_Map_t   = typename ssc::Arg_Mapping::Arg_Map_t;   // Use std::vector<std::pair<std::string, std::string>> to Store Passed-Arguments.
    using std::size_t;                                          // Use size_t Generally
    using ssc::u8_t, ssc::u16_t, ssc::u32_t, ssc::u64_t,    // Concretely Define Unsigned Integer Types
          ssc::i8_t, ssc::i16_t, ssc::i32_t, ssc::i64_t;    // Concretely Define Signed Integer Types

    /* Structure Describing an Operating-System-Level Abstraction of
     * Memory-Mapped Files: The Input and Output Files of a 3crypt Invocation
     */
    struct File_Data
    {
        // Platform-Specific File_Data Variables
#if   defined( __gnu_linux__ )
        int  input_fd;
        int output_fd;
#elif defined( _WIN64 )
        HANDLE  input_handle;
        HANDLE output_handle;
        HANDLE  input_filemapping;
        HANDLE output_filemapping;
#else
    #error "struct File_Data only defined for Gnu/Linux and 64-bit MS Windows"
#endif
        // Platform-Agnostic File_Data variables
        u8_t *  input_map;
        u8_t * output_map;
        u64_t  input_filesize;
        u64_t output_filesize;
    }; /* ! struct File_Data */
    /* Structure Describing a File-Header: The Beginning Metadata of
     * 3crypt-Related files ( i.e. 3CRYPT_CBC_V2 ).
     */
    template <size_t ID_Bytes>
    struct SSPKDF_Header
    {
        char  id          [ID_Bytes];   // i.e. "3CRYPT_CBC_V2"
        u64_t total_size;               // i.e. 1'000'000, for a 3crypt File 1'000'000 Bytes Large
        u8_t  tweak       [Tweak_Bytes];// i.e. (128 / 8) Bytes
        u8_t  sspkdf_salt [Salt_Bytes]; // i.e. (128 / 8) Bytes
        u8_t  cbc_iv      [Block_Bytes];// i.e. (512 / 8) Bytes
        u32_t num_iter;                 // i.e. 1'000'000 Iterations
        u32_t num_concat;               // i.e. 1'000'000 Concatenations
                                        // Compile-Time-Constant, Describing the Combined Size in Bytes
        static constexpr auto const Total_Size = sizeof(id) + sizeof(total_size) + sizeof(tweak) + \
                                                 sizeof(sspkdf_salt) + sizeof(cbc_iv) + sizeof(num_iter) + \
                                                 sizeof(num_concat);
    };

    void      open_files    (File_Data       & f_data,  // Open the input file by `input_filename`, the output file by `output_filename`
                             char const * __restrict input_filename,
                             char const * __restrict output_filename);
    void      close_files   (File_Data const & f_data); // Close the input and output files by their OS-Specific File Handlers
    void      map_files     (File_Data       & f_data); // Map the input and output files by their OS-Specific File Handlers
    void      unmap_files   (File_Data const & f_data); // Un-Map the input and output files by their OS-Specific File Handlers
    void      sync_map      (File_Data const & f_data); // Flush Data Written to The Memory-Mapped Output-File
#if   defined( __gnu_linux__ )
    void      set_file_size(int const file_d, size_t const new_size);       // Gnu/Linux-Specific Function for Truncating a File
#elif defined( _WIN64 )
    void      set_file_size(HANDLE handle, size_t const new_size);          // Win64-Specific Function for Truncating a File
#endif
    void      set_file_size(char const * filename, size_t const new_size);  // Generic Function for Truncating a File
} /* ! namespace threecrypt */
#endif /* ! defined 3CRYPT_HH */
