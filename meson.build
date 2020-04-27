# Define project.
project('3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release',
                                           'optimization=3', 'cpp_eh=none'])
# Get C++ compiler.
cc = meson.get_compiler('cpp')
# Get the host's operating system.
os = host_machine.system()
# Default source files.
source    = ['main.cc','threecrypt.cc']
include   = []
lib       = []
depends   = []
cpp_flags = []

_Define_Flag_Prefix = '-D'
# The define flag prefix is different on Windows with MSVC compiler.
if os == 'windows' and cc.get_id() == 'msvc'
	_Define_Flag_Prefix = '/D'
endif

# Handle BSD-specifics.
if   os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	include += '/usr/local/include'
	lib     += '/usr/local/lib'
# Handle GNU/Linux-specifics.
elif os == 'linux'
	include += '/usr/include'
# Handle Windows-specifics.
elif os == 'windows'
	include += 'C:/include'
	lib     += 'C:/lib'
else
	assert(false)
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
if get_option('enable_debugging_symbols') and cc.get_id() == 'gcc' or cc.get_id() == 'clang'
	cpp_flags += '-g'
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
else
	assert(false)
endif
# On OSX, this cpp flag is required for access to memset_s, which we use to securely destroy memory.
if os == 'darwin'
	_flag = _Define_Flag_Prefix + '__STDC_WANT_LIB_EXT1__=1'
	cpp_flags += _flag
endif

if os != 'windows'
	executable('3crypt', sources: source, dependencies: depends,
		   include_directories: include, install: true,
		   cpp_args: cpp_flags)
else
	executable('3crypt', sources: source, dependencies: depends,
	           include_directories: include, install: true,
		   cpp_args: cpp_flags, install_dir: 'C:/bin')
endif
