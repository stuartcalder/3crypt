#include "vgp.hpp"

int main()
{
  VGP vgp;
  {//+
    uint8_t key[64];
    uint8_t iv [64];
    for( int i = 0; i < 64; ++i ) {
      key[i] = static_cast<uint8_t>(i);
      iv[i] =  static_cast<uint8_t>(63) - i;
    }
    vgp.cbc_encrypt_file( "original_file", "encrypted_file", key, iv );
    vgp.cbc_decrypt_file( "encrypted_file", "decrypted_file", key );
    explicit_bzero( key, sizeof(key) );
  }//-
}
