project('3crypt',
	'c',
	default_options: ['c_std=c17', 'optimization=3', 'buildtype=release', 'strip=true'])
_PROJECT = '3crypt'
_LANG    = 'c'
_UNIXLIKE_OPERATING_SYSTEMS  = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux']
_SUPPORTED_OPERATING_SYSTEMS = _UNIXLIKE_OPERATING_SYSTEMS + ['windows']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
_SUPPORTED_COMPILERS         = _GCC_COMPATIBLE_COMPILERS + ['msvc']

compiler = meson.get_compiler(_LANG)
os = host_machine.system()
Base_static = get_option('Base_static')
Base_mlock  = get_option('Base_mlock')
Skc_static  = get_option('Skc_static')
assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build 3crypt using an unsupported operating system!')
assert (compiler.get_id() in _SUPPORTED_COMPILERS, 'You are trying to build 3crypt using an unsupported compiler!')

if os == 'windows' and compiler.get_id() == 'msvc'
  _D = '/D'
else
  _D = '-D'
endif
src = [
  'threecrypt.c',
  'main.c',
  'dragonfly_v1.c',
  'args.c'
  ]
include = [
  ]
lib_dir = [
  ]
lib_depends = [
  ]
lang_flags = [
  ]
gcc_compatible_flags = [
  '-fvisibility=hidden',
  '-fstrict-aliasing',
  '-Wall',
  '-funroll-loops'
  ]
if Base_static
  lang_flags += _D + 'BASE_EXTERN_STATIC_LIB'
endif
if Base_mlock and os != 'openbsd'
  lang_flags += _D + 'BASE_EXTERN_MLOCK'
endif
if Skc_static
  lang_flags += _D + 'SKC_EXTERN_STATIC_LIB'
endif
if os != 'netbsd' and compiler.get_id() != 'clang'
  gcc_compatible_flags += '-flto'
endif
if os == 'darwin'
  lang_flags += _D + '__STDC_WANT_LIB_EXT1__=1'
endif
if os in _UNIXLIKE_OPERATING_SYSTEMS and compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
  lang_flags += gcc_compatible_flags
endif
is_gcc_compatible = (compiler.get_id() in _GCC_COMPATIBLE_COMPILERS)
if os == 'openbsd' or os == 'freebsd' or os == 'darwin'
  include += '/usr/local/include'
  lib_dir += '/usr/local/lib'
elif os == 'netbsd'
  include  += '/usr/local/include'
  include  += '/usr/pkg/include'
  lib_dir += '/usr/local/lib'
  lib_dir += '/usr/pkg/lib'
elif os == 'linux'
  include += '/usr/include'
  if compiler.get_id() == 'gcc'
    lang_flags += '-flto'
  endif
elif os == 'windows'
  include += 'C:/include'
  lib_dir += 'C:/lib'
endif
if get_option('enable_dragonfly_v1')
  lang_flags += _D + 'THREECRYPT_EXTERN_ENABLE_DRAGONFLY_V1'
  if get_option('dragonfly_v1_default_garlic') != 23
    _garlic = get_option('dragonfly_v1_default_garlic').to_string()
    lang_flags += _D + 'THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC' + _garlic
  endif
endif
if get_option('strict_arg_processing')
  lang_flags += _D + 'THREECRYPT_EXTERN_STRICT_ARG_PROCESSING'
endif
if compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
  if get_option('native_optimize')
    lang_flags += '-march=native'
  endif
  if get_option('use_debug_symbols')
    lang_flags += '-g'
  endif
endif
if get_option('debug_build')
  lang_flags += _D + 'THREECRYPT_EXTERN_DEBUG'
endif
if os in ['openbsd', 'freebsd', 'darwin', 'netbsd']
  lib_depends += compiler.find_library('Base', dirs: lib_dir, static: Base_static)
  lib_depends += compiler.find_library('Skc', dirs: lib_dir, static: Skc_static)
  if Base_static
    lib_depends += compiler.find_library('ncurses')
  endif
elif os == 'linux'
  lib_depends += compiler.find_library('Base', static: Base_static)
  lib_depends += compiler.find_library('Skc', static: Skc_static)
  if Base_static
    lib_depends += compiler.find_library('ncurses')
    lib_depends += compiler.find_library('tinfo')
  endif
elif os == 'windows'
  lib_depends += compiler.find_library('Base', dirs: lib_dir, static: Base_static)
  lib_depends += compiler.find_library('Skc', dirs: lib_dir, static: Skc_static)
  if Base_static
    lib_depends += compiler.find_library('bcrypt') #FIXME
  endif
endif

if os != 'windows'
  executable('3crypt', sources: src, dependencies: lib_depends,
	     include_directories: include, install: true,
	     c_args: lang_flags)
  install_man('3crypt.1')
else
  executable('3crypt', sources: src, dependencies: lib_depends,
	     include_directories: include, install: true,
	     c_args: lang_flags, install_dir: 'C:/bin')
endif
