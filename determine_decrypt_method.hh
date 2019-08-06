#ifndef DETERMINE_DECRYPT_METHOD_HH
#define DETERMINE_DECRYPT_METHOD_HH

#include <ssc/files/files.hh>
#include <ssc/general/static_string.hh>

#include "3crypt.hh"
#include "cbc_v1.hh"
#include "cbc_v2.hh"

#include <vector>

namespace threecrypt
{
    static constexpr std::size_t determine_biggest_identifier_string_size()
    {
        std::size_t s = 0;
#ifdef CBC_V2_HH
        if ( sizeof(cbc_v2::CBC_V2_ID) > s ) {
            s = sizeof(cbc_v2::CBC_V2_ID);
        }
#endif
#ifdef CBC_V1_HH
        if ( sizeof(cbc_v1::CBC_V1_ID) > s ) {
            s = sizeof(cbc_v1::CBC_V1_ID);
        }
#endif
        return s;
    }/* ! threecrypt::determine_biggest_identifier_string_size() */
    constexpr std::size_t const Biggest_Identifier_String_Size = determine_biggest_identifier_string_size();

    static constexpr std::size_t determine_smallest_identifier_string_size()
    {
        std::size_t s = Biggest_Identifier_String_Size;
#ifdef CBC_V2_HH
        if ( sizeof(cbc_v2::CBC_V2_ID) < s ) {
            s = sizeof(cbc_v2::CBC_V2_ID);
        }
#endif
#ifdef CBC_V1_HH
        if ( sizeof(cbc_v1::CBC_V1_ID) < s ) {
            s = sizeof(cbc_v1::CBC_V1_ID);
        }
#endif
        return s;
    }/* ! threecrypt::determine_smallest_identifier_string_size() */
    constexpr std::size_t const Smallest_Identifier_String_Size = determine_smallest_identifier_string_size();

    enum class Decryption_Method_e {
        None,
#ifdef CBC_V1_HH
        CBC_V1,
#endif
#ifdef CBC_V2_HH
        CBC_V2,
#endif
        Terminating_Enum
    };
    Decryption_Method_e determine_decrypt_method(char const * filename);
}/* ! namespace threecrypt */

#endif
