# Declare 3crypt project written in C++17 that strips binaries by default
project( '3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release', 'optimization=3' ] )

# Get the C++17 compiler
cc = meson.get_compiler( 'cpp' )

# Define what implementation files are needed to compile 3crypt
_3crypt_src = [ '3crypt.cc', 'cbc_v1.cc', 'cbc_v2.cc', 'determine_decrypt_method.cc',
                'main.cc' ]

# Get ncurses (needs to be installed already on the system)
ncurses_dep = cc.find_library( 'ncurses' )

# Get ssc     (needs to be installed already on the system)
ssc_dep = cc.find_library( 'ssc' )

# Include files in '/usr/local/include'
ssc_inc = include_directories( '/usr/local/include' )

# Build the 3crypt executable
executable( '3crypt', sources: _3crypt_src, dependencies: [ ssc_dep, ncurses_dep ], include_directories: ssc_inc )
