#ifndef THREECRYPT_HH
#define THREECRYPT_HH
/* SSC Library Includes */
#include <ssc/general/arg_mapping.hh>   // include <ssc/general/arg_mapping.hh> for processing command-line arguments
#include <ssc/general/static_string.hh> // include <ssc/general/static_string.hh> for constexpr C-string functionalities
#include <ssc/crypto/operations.hh>     // include <ssc/crypto/opterations.hh> for genericized cryptographic operations
#include <ssc/crypto/threefish.hh>      // include <ssc/crypto/threefish.hh> to use the Threefish tweakable block cipher
#include <ssc/crypto/cbc.hh>            // include <ssc/crypto/cbc.hh> to use Cipher Block Chaining mode with Threefish
#include <ssc/crypto/skein.hh>          // include <ssc/crypto/skein.hh> to use the Skein hash function for its Message Authentication Code functionality
#include <ssc/crypto/sspkdf.hh>         // include <ssc/crypto/sspkdf.hh> to use the SSPKDF key-derivation function
#include <ssc/files/files.hh>           // include <ssc/files/files.hh> for some genericized file-related functions
#include <ssc/interface/terminal.hh>    // include <ssc/interface/terminal.hh> for a terminal interface
#include <ssc/general/integers.hh>      // include <ssc/general/integers.hh> for integer type aliases
/* Platform-Specific Includes */
#if defined(__gnu_linux__)
    #include <sys/types.h> // include <sys/types.h> for some types that we need
    #include <sys/stat.h>  // include <sys/stat.h> so we can use the stat() family of functions
    #include <fcntl.h>     // include <fcntl.h> for the file control options
    #include <sys/mman.h>  // include <sys/mman.h> for the memory-mapping related functions and defines
    #include <unistd.h>    // include <unistd.h> for ftruncate() and truncate() etc etc
#elif defined(_WIN64)
    #include <windows.h>
    #include <memoryapi.h>
#else
    #error "Currently, only Gnu/Linux and MS Windows are implemented."
#endif
/* Standard Library Includes */
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace threecrypt
{
    static_assert(CHAR_BIT == 8);
    static constexpr auto const Salt_Bits   = 128;             // Sufficiently big 128-bit salt for SSPKDF.
    static constexpr auto const Salt_Bytes  = Salt_Bits / 8;
    static constexpr auto const Tweak_Bits  = 128;             // Required 128-bit tweak for Threefish.
    static constexpr auto const Tweak_Bytes = Tweak_Bits / 8;
    static constexpr auto const Block_Bits  = 512;             // Use the 512-bit block variants for algorithms here.
    static constexpr auto const Block_Bytes = Block_Bits / 8;
    static constexpr auto const MAC_Bytes   = Block_Bytes;     /* Use the same number of bytes of Message Authentication Code
                                                                  as is in the block. */
    static constexpr auto const   Max_Password_Length = 80;      // Arbitrarily set 80 as the longest legal password.
    static constexpr auto const & Help_String = "Usage: 3crypt [Mode] [Switch...]\n"
                                                "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; not 3crypt -e -ifile)\n"
                                                "Modes:\n"
                                                "-e, --encrypt  Symmetric encryption mode; encrypt a file using a passphrase.\n"
                                                "-d, --decrypt  Symmetric decryption mode; decrypt a file using a passphrase.\n"
                                                "Switches:\n"
                                                "-i, --input-file  Input file ; Must be specified for symmetric encryption and decryption modes.\n"
                                                "-o, --output-file Output file; For symmetric encryption and decryption modes. Optional for encryption.";
    static constexpr auto const & Help_Suggestion = "( Use 3crypt --help for more information )";
    using Threefish_t = ssc::Threefish<Block_Bits>;              // Abstractly define the desired cryptographic primitives.
    using Skein_t     = ssc::Skein    <Block_Bits>;
    using CBC_t       = ssc::CBC<Threefish_t, Block_Bits>;
    using Arg_Map_t   = typename ssc::Arg_Mapping::Arg_Map_t;
    using std::size_t; // Use more conveniently named types
    using ssc::u8_t, ssc::u16_t, ssc::u32_t, ssc::u64_t,
          ssc::i8_t, ssc::i16_t, ssc::i32_t, ssc::i64_t;

    struct File_Data
    {
        // Platform specific File_Data variables
#if   defined(__gnu_linux__)
        int  input_fd;
        int output_fd;
#elif defined(_WIN64)
        HANDLE  input_handle;
        HANDLE output_handle;
        HANDLE  input_filemapping;
        HANDLE output_filemapping;
#else
    #error "struct File_Data only defined for Gnu/Linux and MS Windows"
#endif
        // Platform agnostic File_Data variables
        u8_t *  input_map;
        u8_t * output_map;
        u64_t  input_filesize;
        u64_t output_filesize;
    };
    template <size_t ID_Bytes>
    struct SSPKDF_Header
    {
        char  id          [ID_Bytes];
        u64_t total_size;
        u8_t  tweak       [Tweak_Bytes];
        u8_t  sspkdf_salt [Salt_Bytes];
        u8_t  cbc_iv      [Block_Bytes];
        u32_t num_iter;
        u32_t num_concat;
        static constexpr auto const Total_Size = sizeof(id) + sizeof(total_size) + sizeof(tweak) + \
                                                 sizeof(sspkdf_salt) + sizeof(cbc_iv) + sizeof(num_iter) + \
                                                 sizeof(num_concat);
    };

    void      open_files    (File_Data       & f_data, char const * __restrict input_filename, char const * __restrict output_filename);
    void      close_files   (File_Data const & f_data);
    void      map_files     (File_Data       & f_data);
    void      unmap_files   (File_Data const & f_data);
    void      sync_map      (File_Data const & f_data);
#if   defined(__gnu_linux__)
    void      set_file_size(int const file_d, size_t const new_size);
#elif defined(_WIN64)
    void      set_file_size(HANDLE handle, LARGE_INTEGER const new_size);
#endif
    void      set_file_size(char const * filename, size_t const new_size);
} /* ! namespace threecrypt */
#endif /* ! defined 3CRYPT_HH */
