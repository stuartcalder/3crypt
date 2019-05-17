#pragma once
#include "include/general/arg_mapping.hh"
#include "include/crypto/operations.hh"
#include "include/crypto/threefish.hh"
#include "include/crypto/cbc.hh"
#include "include/crypto/skein.hh"
#include "include/crypto/sspkdf.hh"
#include "include/files/files.hh"
#include "include/interface/terminal.hh"
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

class Threecrypt
{
public:
    /* PUBLIC CONSTANTS */
    static constexpr const size_t Salt_Bits = 128;
    static constexpr const size_t Salt_Bytes = Salt_Bits / 8;
    static constexpr const size_t Tweak_Bits = 128;
    static constexpr const size_t Tweak_Bytes = Tweak_Bits / 8;
    static constexpr const size_t Block_Bits = 512;
    static constexpr const size_t Block_Bytes = Block_Bits / 8;
    static constexpr const size_t MAC_Bytes   = Block_Bytes;
    static constexpr const size_t Max_Password_Length = 64;
    static constexpr const auto & Threecrypt_CBC_V1 = "3CRYPT_CBC_V1";
    using Threefish_t = Threefish< Block_Bits >;
    using Skein_t     = Skein    < Block_Bits >;
    using CBC_t       = CBC< Threefish_t, Block_Bits >;
    enum class Mode {
        None, Encrypt_File, Decrypt_File
    };
    /* INTERNAL STRUCTS */
    struct File_Data {
        int           input_fd;
        int          output_fd;
        uint8_t     *input_map;
        uint8_t    *output_map;
        size_t  input_filesize;
        size_t output_filesize;
    };
    /*
    * It is significant that all the types in struct Header be explicitly
    * defined in size, as Headers are copied in and out of memory-mapped
    * files in-place 
    */
    template< size_t ID_Bytes >
    struct Header {
        uint8_t  id         [ ID_Bytes ];
        uint64_t total_size;
        uint8_t  tweak      [ Tweak_Bytes ];
        uint8_t  sspkdf_salt[ Salt_Bytes  ];
        uint8_t  cbc_iv     [ Block_Bytes ];
        uint32_t num_iter;
        uint32_t num_concat;
    };
    using CBC_V1_Header_t = Header< sizeof(Threecrypt_CBC_V1) - 1 >;
    /* CONSTRUCTOR(S) */
    Threecrypt() = delete;
    Threecrypt(const int argc, const char * argv[]);
private:
    /* PRIVATE DATA */
    Mode                   __mode = Mode::None;
    Arg_Mapping::Arg_Map_t __option_argument_pairs;
/* PRIVATE FUNCTIONS */
    void   _process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map);
    auto   _get_mode_c_str(const Mode m) const -> const char *;
    void   _set_mode(const Mode m);
    void   _print_help() const;
    void   _symmetric_encrypt_file() const;
    size_t _calculate_post_encryption_size(const size_t pre_encr_size) const;
    void   _stretch_fd_to(const int fd, const size_t size) const;
    void   _symmetric_decrypt_file() const;
    void   _open_files(struct File_Data & f_data,
                       const char * const input_filename,
                       const char * const output_filename) const;
    void   _close_files(struct File_Data & f_data) const;
    void   _map_files(struct File_Data & f_data) const;
    void   _unmap_files(struct File_Data & f_data) const;
    void   _sync_map(struct File_Data & f_data) const;
};
