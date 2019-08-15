#ifndef CBC_V2_HH
#define CBC_V2_HH

#include "3crypt.hh"
#include "input_abstraction.hh"

namespace threecrypt::cbc_v2
{
    // Constant Definitions
    static constexpr auto const & CBC_V2_ID = "3CRYPT_CBC_V2";
    using CBC_V2_Header_t = SSPKDF_Header<sizeof(CBC_V2_ID)>;

    void CBC_V2_encrypt(Input_Abstraction const & input_abstr);
    void CBC_V2_decrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename);
    void dump_header   (char const * filename);
}
#endif /* ! define CBC_V2_HH */
