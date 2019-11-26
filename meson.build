#Define project
project('3crypt', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release',
                                           'optimization=3', 'cpp_eh=none'])
#Get compiler
cc = meson.get_compiler('cpp')
os = host_machine.system()
source    = ['main_control_unit.cc', 'main.cc']
include   = []
lib       = []
depends   = []
cpp_flags = []

define_flag_prefix = '-D'
if os == 'windows'
	define_flag_prefix = '/D'
endif

if   os == 'openbsd'
	include += '/usr/local/include'
	lib     += '/usr/local/lib'
elif os == 'linux'
	include += '/usr/include'
elif os == 'windows'
	include += 'C:/include'
	lib     += 'C:/lib'
else
	assert(false)
endif

if get_option('enable_experimental_features')
	flag = define_flag_prefix + '__SSC_ENABLE_EXPERIMENTAL'
	cpp_flags += flag
endif

if os == 'openbsd'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc', dirs: lib)
elif os == 'linux'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc')
elif os == 'windows'
	depends += cc.find_library('bcrypt')
	depends += cc.find_library('ssc', static: true, dirs: lib)
	cpp_flags       += '/D__IMPORT_STATIC'
else
	assert(false)
endif

executable('3crypt', sources: source, dependencies: depends,
	   include_directories: include, install: true,
	   cpp_args: cpp_flags)
