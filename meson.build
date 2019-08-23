#Define project
project( '3crypt', 'cpp', default_options: [ 'cpp_std=c++17', 'strip=true', 'buildtype=release',
                                             'optimization=3', 'cpp_eh=none' ] )
#Get compiler
cc = meson.get_compiler( 'cpp' )
os = host_machine.system()
#Determine what implementation files are needed
_3crypt_src = [ 'cbc_v2.cc', 'determine_decrypt_method.cc', 'main.cc' ]
if os != 'windows'
    _3crypt_src += 'cbc_v1.cc'
endif
#Determine 3crypt library dependencies & header includes
_3crypt_dep_array = []
ssc_inc_array     = []
if os == 'linux'
    _3crypt_dep_array += cc.find_library( 'ncurses' )
    _3crypt_dep_array += cc.find_library( 'ssc' )
    ssc_inc_array     += include_directories( '/usr/include' )
    executable( '3crypt', sources: _3crypt_src, dependencies:
        _3crypt_dep_array, include_directories: ssc_inc_array, install: true )
elif os == 'windows'
    _3crypt_dep_array += cc.find_library( 'bcrypt' )
    _3crypt_dep_array += cc.find_library( 'ssc', static: true, dirs: 'C:/local/lib' )
    ssc_inc_array     += include_directories( 'C:/local/include' )
    executable( '3crypt', sources: _3crypt_src, dependencies:
        _3crypt_dep_array, include_directories: ssc_inc_array, install: true,
        cpp_args: '-DIMPORT_STATIC' )
else
    assert( false )
endif
