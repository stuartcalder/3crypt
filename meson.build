# Define project.
project('3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release',
                                           'optimization=3', 'cpp_eh=none'])
# Get C++ compiler.
cc = meson.get_compiler('cpp')
# Get the host's operating system.
os = host_machine.system()
# Default source files.
###source    = ['main_control_unit.cc', 'main.cc']
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
if   os == 'openbsd' or os == 'freebsd'
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

if get_option('enable_cbc_v2')
	_flag = _Define_Flag_Prefix + '__3CRYPT_ENABLE_CBC_V2'
	cpp_flags += _flag
endif
if get_option('enable_ctr_v1')
	_flag = _Define_Flag_Prefix + '__3CRYPT_ENABLE_CTR_V1'
	cpp_flags += _flag
endif

if os == 'openbsd' or os == 'freebsd'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc', dirs: lib)
elif os == 'linux'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc')
elif os == 'windows'
	depends += cc.find_library('bcrypt')
	depends += cc.find_library('ssc', static: true, dirs: lib)
	_flag = _Define_Flag_Prefix + '__IMPORT_STATIC'
	cpp_flags += _flag
else
	assert(false)
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
