#ifndef VGP_HPP
#define VGP_HPP
#include "include/crypto/threefish.hpp"
#include "include/crypto/cbc.hpp"
#include "include/files/files.hpp"
#include <memory>
#include <string>

class VGP
{
public:
  using cbc_t = CBC< ThreeFish<512>, 512 >;
  static constexpr const size_t Block_Bytes = (ThreeFish<512>::Number_Words * 8);
  static constexpr const bool Debug = true;

  void cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key, const uint8_t * const iv = nullptr) const;
  void cbc_decrypt_file(const char * const input_filename, const char * const output_filename,
                        const uint8_t * const key) const;
private:
};

#endif
