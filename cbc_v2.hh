#ifndef CBC_V2_HH
#define CBC_V2_HH

#include "3crypt.hh"

namespace threecrypt::cbc_v2
{
    // Constant Definitions
    static constexpr auto const & CBC_V2_ID = "3CRYPT_CBC_V2";
    using CBC_V2_Header_t = SSPKDF_Header<sizeof(CBC_V2_ID)>;

#if 0
    void CBC_V2_encrypt(Arg_Map_t const &);
    void CBC_V2_decrypt(Arg_Map_t const &);
#endif
    void CBC_V2_encrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename);
    void CBC_V2_decrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename);
}
#endif /* ! define CBC_V2_HH */
