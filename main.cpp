#if 0
#include "vgp.hpp"
#endif
#include "include/crypto/skein.hpp"
#include "include/general/print.hpp"

int main()
{
  Skein<512> skein;
  uint8_t in[] = { 0xff };
  uint8_t out[ 512 / 8 ] = { 0 };
  skein.hash( in, out, sizeof(in) );

  constexpr const auto & p8buf = print_integral_buffer<uint8_t>;
  std::printf("IN:\n");
  p8buf( in,  sizeof(in) );
  std::printf("OUT:\n");
  p8buf( out, sizeof(out) );
}

#if 0
int main()
{
  VGP vgp;
  {//+
    uint8_t key[64];
    uint8_t iv [64];
    //Generate a random key
    VGP::generate_random_bytes( key, sizeof(key) );
    VGP::generate_random_bytes( iv, sizeof(iv) );
    //Generate a random IV
    VGP::cbc_encrypt_file( "original_file", "encrypted_file", key, iv, (1024 * 1024 * 20) );
    VGP::cbc_decrypt_file( "encrypted_file", "decrypted_file", key, (1024 * 1024 * 20) );
    explicit_bzero( key, sizeof(key) );
  }//-
}
#endif
