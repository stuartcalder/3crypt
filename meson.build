# Declare 3crypt project written in C++17 that strips binaries by default
project( '3crypt', 'cpp', default_options: [ 'cpp_std=c++17', 'strip=true',
    'buildtype=release', 'optimization=3' ] )

# Get the C++17 compiler
cc = meson.get_compiler( 'cpp' )

# Define what implementation files are needed to compile 3crypt
_3crypt_src = [ '3crypt.cc', 'cbc_v1.cc', 'cbc_v2.cc', 'determine_decrypt_method.cc',
                'main.cc' ]
_3crypt_dep_array = []
if host_machine.system() == 'linux'
    _3crypt_dep_array += cc.find_library( 'ncurses' )
endif

# Get ssc     (needs to be installed already on the system)
if host_machine.system() == 'linux'
    _3crypt_dep_array += cc.find_library( 'ssc' )
elif host_machine.system() == 'windows'
    _3crypt_dep_array += cc.find_library( 'ssc', static: true, dirs:
    'C:/3crypt/' )
else
    assert( false )
endif

ssc_inc_arr = []
if host_machine.system() == 'linux'
    ssc_inc_arr += include_directories( '/usr/local/include' )
elif host_machine.system() == 'windows'
    ssc_inc_arr += include_directories( 'C:/local/include' )
endif

# Build the 3crypt executable
if host_machine.system() == 'linux'
    executable( '3crypt', sources: _3crypt_src, dependencies: _3crypt_dep_array,
        include_directories: ssc_inc_arr, install: true )
elif host_machine.system() == 'windows'
    executable( '3crypt', sources: _3crypt_src, dependencies:
        _3crypt_dep_array, include_directories: ssc_inc_arr, install: true,
        cpp_args: '-DIMPORT_STATIC' )
endif
