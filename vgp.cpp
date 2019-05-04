#include "include/files/files.hpp"
#include "vgp.hpp"

#ifdef __gnu_linux__
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/mman.h>
  #include <unistd.h>
#else
  #error "Only gnu/linux implemented"
#endif

VGP::VGP(const int argc, const char * argv[])
{
  using namespace std;

  //Get a mapping of the c args
  Arg_Mapping args{ argc, argv };
  _process_arg_mapping( args.get() );
  switch( _mode ) {
    default:
      fprintf( stderr, "ERROR: No mode selected. (i.e. -e or -d)\n" );
      _print_help();
      exit( EXIT_FAILURE );
    case( Mode::Encrypt_File ):
      _symmetric_encrypt_file();
      break;
    case( Mode::Decrypt_File ):
      break;
  }
}

void VGP::_process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map)
{
  using namespace std;

  for( int i = 1; i < a_map.size(); ++i ) { // start counting @ 1 to skip the first arg (the name of the binary)
    /* Help Switch */
    if( a_map[i].first == "-h" || a_map[i].first == "--help" ) {
      _print_help();
      exit( EXIT_SUCCESS );
    }
    /* Encrypt file switch */
    else if( a_map[i].first == "-e" || a_map[i].first == "--encrypt" ) {
      _set_mode( Mode::Encrypt_File );
    }
    /* Decrypt file switch */
    else if( a_map[i].first == "-d" || a_map[i].first == "--decrypt" ) {
      _set_mode( Mode::Decrypt_File );
    }
    /* Disallow floating arguments */
    else if( a_map[i].first.size() == 0 && a_map[i].second.size() != 0 ) {
      fprintf( stderr, "Error: Floating arguments ( %s ) not allowed.\n",
                    a_map[i].second.c_str() );
      exit( EXIT_FAILURE );
    }
    /* Assumed legal option-argument pair is stored */
    else {
      _option_argument_pairs.push_back( a_map[i] );
    }
  }///////////////////////////////////////////////
}

auto VGP::_get_mode_c_str(const Mode m) const
  -> const char *
{
  switch( m ) {
    default:
      return "Undefined_Mode";
    case( Mode::None ):
      return "None";
    case( Mode::Encrypt_File ):
      return "Encrypt_File";
    case( Mode::Decrypt_File ):
      return "Decrypt_File";
  }
}

void VGP::_set_mode(const Mode m)
{
  using namespace std;

  if( _mode != Mode::None ) {
    fprintf( stderr, "Error: Mode %s already specified. May not specify another.\n\n",
             _get_mode_c_str( _mode ) );
    _print_help();
    exit( EXIT_FAILURE );
  }
  _mode = m;
}

void VGP::_print_help()
{
  std::puts(
    "Usage: vgp [Mode] [Switch...]\n"
    "Arguments to switches MUST be in seperate words. (i.e. vgp -e -i file; not vgp -e -ifile)\n"
    "Modes:\n"
    "-e, --encrypt\tSymmetric encryption mode; encrypt a file.\n"
    "-d, --decrypt\tSymmetric decryption mode; decrypt a file.\n"
    "Switches:\n"
    "-i, --input-file\tInput file; Must be specified for symmetric encryption and decryption modes.\n"
    "-o, --output-file\tOutput file; For symmetric encryption and decryption modes. Optional for encryption; mandatory for decryption."
  );
}

void VGP::_symmetric_encrypt_file() const
{
  using namespace std;

  string input_filename, output_filename;
  //////////Get the input and output filenames///////////////////////
  for( const auto & pair : _option_argument_pairs ) {
    check_file_name_sanity( pair.second, 1 );
    if( pair.first == "-i" || pair.first == "--input-file" ) {
      input_filename = pair.second;
      if( output_filename.size() == 0 ) {
        output_filename = input_filename + ".vgp";
      }
    }
    else if( pair.first == "-o" || pair.first == "--output-file" ) {
      output_filename = pair.second;
    }
    else {
      fprintf( stderr, "Error: unrecognizable switch %s\n" pair.first.c_str() );
      _print_help();
      exit( EXIT_FAILURE );
    }
  }
  if( (input_filename.size() == 0) || (output_filename.size() == 0) ) {
    fprintf( stderr, "Error: Either the input filename or the output filename has a length of zero.\n" );
    _print_help();
    exit( EXIT_FAILURE );
  }
  if( file_exists( output_filename.c_str() ) ) {
    fprintf( stderr, "Error: output file '%s' already seems to exist.\n", output_filename.c_str() );
    exit( EXIT_FAILURE );
  }
  //////////Open the input and output files//////////////////////////
  const int input_fd  = open( input_filename.c_str(),  (O_RDWR | O_CREAT | O_TRUNC), static_cast<mode_t>(0600) ),
            output_fd = open( output_filename.c_str(), (O_RDWR | O_CREAT | O_TRUNC), static_cast<mode_t>(0600) );
  if( input_fd == -1 ) {
    fprintf( stderr, "Error: Unable to open file '%s'\n", input_filename.c_str() );
    exit( EXIT_FAILURE );
  }
  if( output_fd == -1 ) {
    fprintf( stderr, "Error: Unable to open file '%s'\n", output_filename.c_str() );
    exit( EXIT_FAILURE );
  }
  //////////Map the input and output files///////////////////////////
  const size_t input_file_size  = get_file_size( input_fd );
  const size_t output_file_size = _calculate_post_encryption_size( input_file_size );
  // stretch output_file to the correct size
  _stretch_fd_to( output_fd, output_file_size );
  uint8_t * const input_map  = mmap( 0, input_file_size, PROT_READ, MAP_SHARED, input_fd, 0 ),
          * const output_map = mmap( 0, output_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, output_fd, 0 );
  if( input_map == MAP_FAILED ) {
    fprintf( stderr, "Error: Failed to open input map\n" );
    exit( EXIT_FAILURE );
  }
  else if( output_map == MAP_FAILED ) {
    fprintf( stderr, "Error: Failed to open output map\n" );
    exit( EXIT_FAILURE );
  }
  // Generate a header
  struct Header header;
  header.total_size = static_cast<uint64_t>(output_file_size);
  generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
  generate_random_bytes( header.cbc_iv, sizeof(header.cbc_iv) );
  header.num_iter   = 1'000'000;
  header.num_concat = 1'000'000;
  // Copy header into new file
  uint8_t * out = output_map;
  memcpy( out, &header, sizeof(header) );
  out += sizeof(header);
  // Generate key
  const char password[] = "forehead_punch";
  uint8_t derived_key[ Block_Bytes ];
  SSPKDF( derived_key,
          reinterpret_cast<uint8_t *>(password),
          sizeof(password) - 1,
          header.sspkdf_salt,
          header.num_iter,
          header.num_concat );
  // Encrypt file
  {
    CBC_t cbc{ Threefish_t{ derived_key } };
    out += cbc.encrypt( input_map, out, input_file_size, header.cbc_iv );
  }
  // MAC the file
  {
    Skein_t skein;
    skein.MAC( out,
               output_map,
               derived_key,
               output_file_size - MAC_Bytes,
               sizeof(derived_key),
               Block_Bytes );
  }
  // Sync output memory mapping
  if( msync( output_map, output_file_size, MS_SYNC ) == -1 ) {
    fprintf( stderr, "Error: Failed to sync mmap()\n" );
    exit( EXIT_FAILURE );
  }
  // Close memory mappings
  if( munmap( input_map, input_file_size ) == -1 ) {
    fprintf( stderr, "Error: Failed to unmap input file\n" );
    exit( EXIT_FAILURE );
  }
  if( munmap( output_map, output_file_size ) == -1 ) {
    fprintf( stderr, "Error: Failed to unmap output file\n" );
    exit( EXIT_FAILURE );
  }
  // Close open files
  if( close( input_fd ) == -1 ) {
    fprintf( stderr, "Error: Unable to close input file with file-descriptor %d\n", input_fd );
    exit( EXIT_FAILURE );
  }
  if( close( output_fd ) == -1 ) {
    fprintf( stderr, "Error: Unable to close output file with file-descriptor %d\n", output_fd );
    exit( EXIT_FAILURE );
  }
}

size_t VGP::_calculate_post_encryption_size(const size_t pre_encr_size) const
{
  size_t s = pre_encr_size;
  // account for added padding (Block_Bytes)
  if( s < Block_Bytes ) {
    s = Block_Bytes;
  }
  else {
    const auto remain = s % Block_Bytes;
    s += (remain == 0 ? (Block_Bytes) : (remain));
  }
  // account for header at the beginning of the file and the MAC at the end of the file
  return s + sizeof(Header) + MAC_Bytes;
}

void VGP::_stretch_fd_to(const int fd, const size_t size) const
{
  using namespace std;

  if( lseek( fd, size -1, SEEK_SET ) == -1 ) {
    fprintf( stderr, "Error calling lseek() to stretch file descriptor %d\n", fd );
    exit( EXIT_FAILURE );
  }
  if( write( fd, "", 1 ) == -1 ) {
    fprintf( stderr, "Error unable to write last byte of file descriptor %d\n", fd );
    exit( EXIT_FAILURE );
  }
}
