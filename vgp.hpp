#pragma once
#include "include/general/arg_mapping.hpp"
#include "include/crypto/operations.hpp"
#include "include/crypto/threefish.hpp"
#include "include/crypto/skein.hpp"
#include "include/crypto/sspkdf.hpp"
#include "include/crypto/file_encryption.hpp"
#include "include/files/files.hpp"
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

class VGP
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
  static constexpr const size_t ID_Bytes = 16;
  using Threefish_t = Threefish< Block_Bits >;
  using CBC_t       = CBC< Threefish_t, Block_Bits >;
  using Skein_t     = Skein< Block_Bits >;
  enum class Mode {
    None, Encrypt_File, Decrypt_File
  };
/* INTERNAL STRUCTS */
  struct Header {
    uint8_t  id         [ ID_Bytes ];
    uint64_t total_size;
    uint8_t  tweak      [ Tweak_Bytes ];
    uint8_t  sspkdf_salt[ Salt_Bytes  ];
    uint8_t  cbc_iv     [ Block_Bytes ];
    uint32_t num_iter;
    uint32_t num_concat;
  };
/* CONSTRUCTOR(S) */
  VGP() = delete;
  VGP(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  Mode                   _mode = Mode::None;
  Arg_Mapping::Arg_Map_t _option_argument_pairs;
/* PRIVATE FUNCTIONS */
  void _process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map);
  auto _get_mode_c_str(const Mode m) const -> const char *;
  void _set_mode(const Mode m);
  void _print_help() const;
  void _symmetric_encrypt_file() const;
  size_t _calculate_post_encryption_size(const size_t pre_encr_size) const;
  void _stretch_fd_to(const int fd, const size_t size) const;
  void _symmetric_decrypt_file() const;
};
