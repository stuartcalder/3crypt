#pragma once

#ifndef CBC_V1_HH
#define CBC_V1_HH

#include "3crypt.hh"

namespace threecrypt::cbc_v1
{
    // Constant Definitions
    static constexpr auto const & CBC_V1_ID = "3CRYPT_CBC_V1";
    using CBC_V1_Header_t = SSPKDF_Header<ssc::static_strlen(CBC_V1_ID)>;

#if 0
    void CBC_V1_encrypt(Arg_Map_t const &);
    void CBC_V1_decrypt(Arg_Map_t const &);
#endif
    void CBC_V1_encrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename);
    void CBC_V1_decrypt(char const * __restrict input_filename,
                        char const * __restrict output_filename);

}
#endif /* ! defined CBC_V1_HH */
