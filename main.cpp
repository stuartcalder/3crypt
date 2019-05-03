#include "vgp.hpp"
#include "include/general/print.hpp"

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
