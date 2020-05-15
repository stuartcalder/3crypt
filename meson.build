# Define project.
project('3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release',
                                           'optimization=3', 'cpp_eh=none'])
# Determine the compiler and the operating system.
cc = meson.get_compiler('cpp')
os = host_machine.system()
# Assert that we are building on a supported operating system with a supported compiler.
assert (
	os == 'openbsd' or os == 'freebsd' or os == 'darwin' or
	os == 'linux' or
	os == 'windows',
	'You are trying to build 3crypt on an unsupported operating system!'
)
assert (
	cc.get_id() == 'gcc' or cc.get_id() == 'clang' or cc.get_id() == 'msvc',
	'You are trying to build 3crypt using an unsupported compiler!'
)
# Default source files.
source    = ['main.cc','threecrypt.cc']
include   = []
lib       = []
depends   = []
cpp_flags = []

# The define flag prefix is different on Windows with MSVC compiler.
if os == 'windows' and cc.get_id() == 'msvc'
	_Define_Flag_Prefix = '/D'
else
	_Define_Flag_Prefix = '-D'
endif
# Determine whether the compiler is compatible with gcc flags.
is_gcc_compatible = (cc.get_id() == 'gcc' or cc.get_id() == 'clang')

# Handle BSD-specifics.
if   os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	include += '/usr/local/include'
	lib     += '/usr/local/lib'
# Handle GNU/Linux-specifics.
elif os == 'linux'
	include += '/usr/include'
	if cc.get_id() == 'gcc'
		cpp_flags += '-flto'
	endif
# Handle Windows-specifics.
elif os == 'windows'
	include += 'C:/include'
	lib     += 'C:/lib'
endif

# Enable Dragonfly V1?
if get_option('enable_dragonfly_v1')
	_flag = _Define_Flag_Prefix + '__3CRYPT_ENABLE_DRAGONFLY_V1'
	cpp_flags += _flag
endif
# Enable CBC_V2?
if get_option('enable_cbc_v2')
	_flag = _Define_Flag_Prefix + '__3CRYPT_ENABLE_CBC_V2'
	cpp_flags += _flag
endif
# Include debugging symbols?
if is_gcc_compatible and get_option('enable_debugging_symbols')
	cpp_flags += '-g'
endif
# Specify a default garlic?
if get_option('default_garlic') != 23
	_garlic = get_option('default_garlic').to_string()
	_flag = _Define_Flag_Prefix + '__3CRYPT_DRAGONFLY_V1_DEFAULT_GARLIC=' + _garlic
	cpp_flags += _flag
endif

# On OSX, this cpp flag is required for access to memset_s, which we use to securely destroy memory.
if os == 'darwin'
	_flag = _Define_Flag_Prefix + '__STDC_WANT_LIB_EXT1__=1'
	cpp_flags += _flag
endif
# Handle the BSD systems.
if os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc', dirs: lib)
# Handle GNU/Linux.
elif os == 'linux'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc')
# Handle Win64.
elif os == 'windows'
	depends += cc.find_library('bcrypt')
	depends += cc.find_library('ssc', static: true, dirs: lib)
	_flag = _Define_Flag_Prefix + '__IMPORT_STATIC'
	cpp_flags += _flag
endif

if os != 'windows'
	executable('3crypt', sources: source, dependencies: depends,
		   include_directories: include, install: true,
		   cpp_args: cpp_flags)
	install_man('3crypt.1')
      
else
	executable('3crypt', sources: source, dependencies: depends,
	           include_directories: include, install: true,
		   cpp_args: cpp_flags, install_dir: 'C:/bin')
endif
