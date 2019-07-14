#pragma once

#include "3crypt.hh"

namespace threecrypt::cbc_v1
{
    // Constant Definitions
    static constexpr auto const & CBC_V1_ID = "3CRYPT_CBC_V1";
    static constexpr bool const Enable_Stdout = true;
    using CBC_V1_Header_t = SSPKDF_Header<ssc::static_strlen(CBC_V1_ID)>;

    void CBC_V1_encrypt(Arg_Map_t const &);
    void CBC_V1_decrypt(Arg_Map_t const &);
}
