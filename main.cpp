#include "vgp.hpp"

int main()
{
  VGP vgp;
  {//+
    const std::string filename{ "database.twofish" };
    const std::string outputname{ "database.twofish.threefish" };
    uint8_t key[64];
    uint8_t iv [64];
    for( int i = 0; i < 64; ++i ) {
      key[i] = static_cast<uint8_t>(i);
      iv[i] =  static_cast<uint8_t>(63) - i;
    }
    vgp.cbc_encrypt_file( &filename, key, iv, &outputname );
    explicit_bzero( key, sizeof(key) );
  }//-
}
