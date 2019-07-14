#pragma once
#include <ssc/general/arg_mapping.hh>
#include <ssc/general/static_string.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/cbc.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/sspkdf.hh>
#include <ssc/files/files.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/general/integers.hh>

#if defined(__gnu_linux__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <unistd.h>
#else
    #error "Currently, only Gnu/Linux is implemented"
#endif

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace threecrypt
{
    constexpr auto const Salt_Bits   = 128;             // Sufficiently big 128-bit salt for SSPKDF.
    constexpr auto const Salt_Bytes  = Salt_Bits / 8;
    constexpr auto const Tweak_Bits  = 128;             // Required 128-bit tweak for Threefish.
    constexpr auto const Tweak_Bytes = Tweak_Bits / 8;
    constexpr auto const Block_Bits  = 512;             // Use the 512-bit block variants for algorithms here.
    constexpr auto const Block_Bytes = Block_Bits / 8;
    constexpr auto const MAC_Bytes   = Block_Bytes;     /* Use the same number of bytes of Message Authentication Code
                                                           as is in the block. */
    constexpr auto const Max_Password_Length = 80;      // Arbitrarily set 80 as the longest legal password.
    using Threefish_t = ssc::Threefish<Block_Bits>;     // Abstractly define the desired cryptographic constructs.
    using Skein_t     = ssc::Skein    <Block_Bits>;
    using CBC_t       = ssc::CBC<Threefish_t, Block_Bits>;
    using Arg_Map_t   = typename ssc::Arg_Mapping::Arg_Map_t;
    using std::size_t; // Use more conveniently named types
    using ssc::u8_t;
    using ssc::u16_t;
    using ssc::u32_t;
    using ssc::u64_t;
    using ssc::i8_t;
    using ssc::i16_t;
    using ssc::i32_t;
    using ssc::i64_t;

    struct File_Data {
        // The variables of File_Data below this comment are platform-specific.
#if defined(__gnu_linux__)
        int     input_fd;
        int     output_fd;
#else
#error "struct File_Data currently only defined for Gnu/Linux"
#endif
        // The variables of File_Data below this comment are guaranteed to exist on all platforms.
        u8_t  * input_map;
        u8_t  * output_map;
        size_t  input_filesize;
        size_t  output_filesize;
    };
    template <size_t ID_Bytes>
    struct SSPKDF_Header {
        char id          [ID_Bytes];
        u64_t total_size;
        u8_t tweak       [Tweak_Bytes];
        u8_t sspkdf_salt [Salt_Bytes];
        u8_t cbc_iv      [Block_Bytes];
        u32_t num_iter;
        u32_t num_concat;
    };

    void      print_help();
    void      open_files(File_Data & f_data, char const *input_filename, char const *output_filename);
    void      close_files(File_Data & f_data);
    void      map_files(File_Data & f_data);
    void      unmap_files(File_Data & f_data);
    void      sync_map(File_Data & f_data);
#if defined(__gnu_linux__)
    void      set_file_size(int const file_d, size_t const new_size);
#endif
    void      set_file_size(char const *filename, size_t const new_size);
} /* ! namespace threecrypt */
