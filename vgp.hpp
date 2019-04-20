#pragma once
#include "include/crypto/threefish_precomputed_keyschedule.hpp"
#include "include/crypto/cbc.hpp"
#include "include/files/files.hpp"
#include "include/general/arg_mapping.hpp"
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

class VGP
{
public:
/* PUBLIC CONSTANTS */
  using Threefish_t = Threefish_Precomputed_Keyschedule<512>;
  using cbc_t = CBC< Threefish_t, Threefish_t::Key_Bits >;
  enum class Action {
    None, Encrypt_File, Decrypt_File
  };
  static constexpr const size_t Block_Bytes = (Threefish_t::Number_Words * 8);
  static constexpr const size_t Default_File_Buffer_Size = 1024 * 1024 * 10; // 10 MiB
  static constexpr const bool   Debug = true;
/* CONSTRUCTOR(S) */
  VGP(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  Action                 _action = Action::None;
  Arg_Mapping::Arg_Map_t _option_argument_pairs;
/* PRIVATE FUNCTIONS */
  void generate_random_bytes(uint8_t * const buffer, size_t num_bytes) const;
  void cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key, const uint8_t * const iv,
                        const size_t file_buffer_size = Default_File_Buffer_Size);
  void cbc_decrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key,
                        const size_t file_buffer_size = Default_File_Buffer_Size);
  void process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map);
  inline auto get_action_c_str(const Action a) const -> const char *;
  void set_action(const Action a);
  void print_help();
};
