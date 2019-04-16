#ifndef VGP_HPP
#define VGP_HPP
#include "include/crypto/threefish_precomputed_keyschedule.hpp"
#include "include/crypto/cbc.hpp"
#include "include/files/files.hpp"
#include <memory>
#include <string>

class VGP
{
public:
  using Threefish_t = Threefish_Precomputed_Keyschedule<512>;
  using cbc_t = CBC< Threefish_t, Threefish_t::Key_Bits >;
  static constexpr const size_t Block_Bytes = (Threefish_t::Number_Words * 8);
  static constexpr const bool Debug = true;

  void cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key, const uint8_t * const iv) const;
  void cbc_decrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key) const;
private:
};

#endif
