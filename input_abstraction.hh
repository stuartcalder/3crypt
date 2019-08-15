#pragma once

#include <string>
#include <utility>
#include <ssc/general/integers.hh>

namespace threecrypt
{
    struct Input_Abstraction
    {
        std::string    input_filename;
        std::string   output_filename;
        u32_t       number_iterations;
        u32_t   number_concatenations;
    };/* ! struct Input_Abstraction */
}/* ! namespace threefish */
