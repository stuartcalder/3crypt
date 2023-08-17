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
SSC_static  = get_option('SSC_static')  # Import SSC as a static library?
SSC_memlock = get_option('SSC_memlock') # Enable SSC Memory Locking?
PPQ_static  = get_option('PPQ_static')  # Import PPQ as a static library?
assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build 3crypt using an unsupported operating system!')
assert (compiler.get_id() in _SUPPORTED_COMPILERS, 'You are trying to build 3crypt using an unsupported compiler!')

# Use /D to define macros on the command-line on Windows; -D on all other operating systems.
if os == 'windows' and compiler.get_id() == 'msvc'
  _D = '/D'
else
  _D = '-D'
endif

src = [
  'Threecrypt.c',
  'Main.c',
  'DragonflyV1.c',
  'CommandLineArg.c'
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

if SSC_static
  # Import SSC as a static library.
  lang_flags += _D + 'SSC_EXTERN_STATIC_LIB'
endif

if SSC_memlock and os != 'openbsd'
  # Enable memory locking as requested on all supported platforms except OpenBSD.
  lang_flags += _D + 'SSC_EXTERN_MEMLOCK'
endif

if PPQ_static
  # Import PPQ as a static library.
  lang_flags += _D + 'PPQ_EXTERN_STATIC_LIB'
endif

if os != 'netbsd' and compiler.get_id() != 'clang'
  # Enable link-time optimization on platforms other than NetBSD.
  gcc_compatible_flags += '-flto'
endif

if os == 'darwin'
  # On MacOS we require this macro #define'd to 1 for access to memset_s.
  lang_flags += _D + '__STDC_WANT_LIB_EXT1__=1'
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS and compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
  # Enable GCC-specific flags.
  lang_flags += gcc_compatible_flags
endif

is_gcc_compatible = (compiler.get_id() in _GCC_COMPATIBLE_COMPILERS)
_LIB_DIRS = {
  'bsd':   ['/usr/lib', '/usr/local/lib'],
  'netbsd': ['/usr/local/lib', '/usr/pkg/lib'],
  'linux': ['/usr/lib64', '/usr/lib'],
  'windows': ['C:\lib']
}
_INC_DIRS = {
  'bsd': ['/usr/local/include'],
  'netbsd': ['/usr/local/include', '/usr/pkg/include'],
  'linux': ['/usr/include'],
  'windows': ['C:\include']
}

if os in ['openbsd', 'freebsd', 'darwin', 'dragonfly']
  # These BSD-like platforms have the same include and lib directories.
  include += _INC_DIRS.get('bsd')
  lib_dir += _LIB_DIRS.get('bsd')
else
  include += _INC_DIRS.get(os)
  lib_dir += _LIB_DIRS.get(os)
  if os == 'linux'
    if compiler.get_id() == 'gcc' or compiler.get_id() == 'clang'
      lang_flags += '-flto'
    endif
  endif
endif

# Enable encrypt/decrypt methods.
if get_option('enable_dragonfly_v1')
  lang_flags += _D + 'THREECRYPT_EXTERN_ENABLE_DRAGONFLY_V1'
  if get_option('dragonfly_v1_default_garlic') != 24
    _garlic = get_option('dragonfly_v1_default_garlic').to_string()
    lang_flags += _D + 'THREECRYPT_EXTERN_DRAGONFLY_V1_DEFAULT_GARLIC=' + _garlic
  endif
endif

# Reject invalid arguments?
if get_option('strict_arg_processing')
  lang_flags += _D + 'THREECRYPT_EXTERN_STRICT_ARG_PROCESSING'
endif

if compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
  # Optimize for the host's ISA.
  if get_option('native_optimize')
    lang_flags += '-march=native'
  endif
  # Include debuggin symbols in the resuling binary.
  if get_option('use_debug_symbols')
    lang_flags += '-g'
  endif
endif

# Enable debug code paths?
if get_option('debug_build')
  lang_flags += _D + 'THREECRYPT_EXTERN_DEBUG'
endif

if os in ['openbsd', 'freebsd', 'darwin', 'netbsd']
  lib_depends += compiler.find_library('SSC', dirs: lib_dir, static: SSC_static)
  lib_depends += compiler.find_library('PPQ', dirs: lib_dir, static: PPQ_static)
  if SSC_static
    # When SSC is linked dynamically we do not need to directly link against ncurses.
    # Since We're statically linking SSC now we do.
    lib_depends += compiler.find_library('ncurses')
  endif
elif os == 'linux'
  lib_depends += compiler.find_library('SSC', static: SSC_static, dirs: lib_dir)
  lib_depends += compiler.find_library('PPQ', static: PPQ_static, dirs: lib_dir)
  if SSC_static
    # When SSC is linked dynamically we do not need to directly link against ncurses or tinfo.
    # Since We're statically linking SSC now we do.
    lib_depends += compiler.find_library('ncurses')
    lib_depends += compiler.find_library('tinfo')
  endif
elif os == 'windows'
  lib_depends += compiler.find_library('SSC', dirs: lib_dir, static: SSC_static)
  lib_depends += compiler.find_library('PPQ', dirs: lib_dir, static: PPQ_static)
  if SSC_static
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
