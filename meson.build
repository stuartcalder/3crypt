# Declare 3crypt project written in C++17 that strips binaries by default
project( '3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true' ] )
cc = meson.get_compiler( 'cpp' )
_3crypt_src = [ '3crypt.cc', 'cbc_v1.cc', 'cbc_v2.cc', 'determine_decrypt_method.cc', 'main.cc' ]
ncurses_dep = cc.find_library( 'ncurses' )
ssc_dep = cc.find_library( 'ssc' )
ssc_inc = include_directories( '/usr/local/include' )
executable( '3crypt', sources: _3crypt_src, dependencies: [ ssc_dep, ncurses_dep ], include_directories: ssc_inc )
