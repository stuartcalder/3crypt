#include "vgp.hpp"

int main()
{
  VGP vgp;
  {//+
    uint8_t key[64];
    uint8_t iv [64];
    for( int i = 0; i < 64; ++i ) {
      key[i] = static_cast<uint8_t>(i);
      iv[i] =  static_cast<uint8_t>(63) - static_cast<uint8_t>(i);
    }
    vgp.cbc_encrypt_file( "original_file", "encrypted_file", key, iv, (1024 * 1024 * 20) );
    vgp.cbc_decrypt_file( "encrypted_file", "decrypted_file", key );
    explicit_bzero( key, sizeof(key) );
  }//-
}
