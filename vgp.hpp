#pragma once
#include "include/general/arg_mapping.hpp"
#include "include/crypto/operations.hpp"
#include "include/crypto/threefish_precomputed_keyschedule.hpp"
#include "include/crypto/cbc.hpp"
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
  using Threefish_t = Threefish_Precomputed_Keyschedule<512>;
  enum class Mode {
    None, Encrypt_File, Decrypt_File
  };
  static constexpr const size_t Block_Bytes = (Threefish_t::Number_Words * 8);
/* CONSTRUCTOR(S) */
  VGP(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  Mode                   _mode = Mode::None;
  Arg_Mapping::Arg_Map_t _option_argument_pairs;
/* PRIVATE FUNCTIONS */
  void process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map);
  inline auto get_mode_c_str(const Mode m) const -> const char *;
  void set_mode(const Mode m);
  void print_help();
  void symmetric_encrypt_file() const;
};
