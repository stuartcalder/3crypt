#include "include/files/files.hpp"
#include "vgp.hpp"
#include <unistd.h>

void VGP::cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                           const uint8_t * const key, const uint8_t * const iv,
                           const size_t file_buffer_size)
{
  using namespace std;
  //Validate arguments somewhat
  if( (key == nullptr) || (iv == nullptr) ) { // Diallow key or iv from being nullptr. That wouldn't make sense.
    fprintf( stderr, "ERROR: VGP::encrypt_file -- Either the key or the initialization vector was a nullptr\n"
                     "The Key: %p\n"
                     "The IV : %p\n", key, iv );
    exit( 1 );
  }

  //Open the input file, and the file to write to.
  cbc_t cbc{ Threefish_t{ reinterpret_cast<const uint64_t*>(key) } }; // feed key
  cbc.manually_set_state( iv );                // & iv into the cbc_t object
  FILE * const input_file = fopen ( input_filename , "rb" );   // open the input file
  FILE * const output_file = fopen( output_filename, "wb" ); // open the output file
  //Check if files successfully opened
  if( (input_file == nullptr) || (output_file == nullptr) ) {
    fprintf( stderr, "Failed to open input file or output file\n"
                     "Input file is: %p\n"
                     "Output file is: %p\n", input_file, output_file );
    exit( 1 );
  }
  size_t bytes_to_encrypt = get_file_size( input_file );           // see how big the file is
  auto buffer = make_unique<uint8_t[]>( file_buffer_size );
  //Write the IV into the beginning of the output file.
  fwrite( iv, 1, Block_Bytes, output_file );
  cbc.manually_set_state( iv );
  while( bytes_to_encrypt > file_buffer_size ) {
    fread( buffer.get(), file_buffer_size, 1, input_file );
    cbc.encrypt_no_padding( buffer.get(), buffer.get(), file_buffer_size );
    fwrite( buffer.get(), file_buffer_size, 1, output_file );
    bytes_to_encrypt -= file_buffer_size;
  }
  {//+
    fread( buffer.get(), 1, bytes_to_encrypt, input_file );
    size_t encrypted = cbc.encrypt( buffer.get(), buffer.get(), bytes_to_encrypt );
    fwrite( buffer.get(), 1, encrypted, output_file );
  }//-
  //Cleanup
  explicit_bzero( buffer.get(), file_buffer_size );
  fclose( input_file );
  fclose( output_file );
}

void VGP::cbc_decrypt_file(const char * const input_filename, const char * const output_filename, const uint8_t * const key,
                           const size_t file_buffer_size)
{
  using namespace std;


  //Validate arguments somewhat
  {//+
    if( (key == nullptr) ) { // Diallow key from being nullptr. That wouldn't make sense.
      fprintf( stderr, "ERROR: VGP::encrypt_file -- Either the key or the initialization vector was a nullptr\n"
                       "The Key: %p\n", key );
      exit( EXIT_FAILURE );
    }
  }//-

  /////////////////Open the input file and the output file////////////////////////////
  cbc_t cbc{ Threefish_t{ reinterpret_cast<const uint64_t*>(key) } };
  FILE * const input_file = fopen( input_filename, "rb" ); // open the input file
  FILE * const output_file = fopen( output_filename, "wb" ); // open the output file
  //////////////////Check if files successfully opened///////////////////////////////
  if( (input_file == nullptr) || (output_file == nullptr) ) {
    fprintf( stderr, "Failed to open input file or output file\n"
                     "Input file is: %p\n"
                     "Output file is: %p\n", input_file, output_file );
    exit( EXIT_FAILURE );
  }
  ////////////////////Check if parameters make sense//////////////////////
  size_t bytes_to_decrypt = get_file_size( input_file );
  if( bytes_to_decrypt < (Block_Bytes * 2) ) {
    fprintf( stderr, "Error: The input file does not appear to be big enough to have been Threefish-512-CBC encrypted.\n" );
    exit( EXIT_FAILURE );
  }
  if( (bytes_to_decrypt % Block_Bytes) != 0 ) {
    fprintf( stderr, "Error: The input files does not appear to be a multiple of Threefish-512-CBC encrypted blocks.\n" );
    exit( EXIT_FAILURE );
  }
  if( (file_buffer_size % Block_Bytes) != 0 ) {
    fprintf( stderr, "Error: The file buffer size must be a multiple of 64-bytes.\n" );
    exit( EXIT_FAILURE );
  }
  //////////////////////////////Get the initialization vector///////////////////////
  {//+
    uint8_t file_iv[ Block_Bytes ];
    bytes_to_decrypt -= fread( file_iv, 1, sizeof(file_iv), input_file );
    cbc.manually_set_state( file_iv );
  }//-
  ///////////////////////////////Decrypt/////////////////////////////////////
  auto buffer = make_unique<uint8_t[]>( file_buffer_size );
  while( bytes_to_decrypt > file_buffer_size ) {
    fread( buffer.get(), file_buffer_size, 1, input_file );
    cbc.decrypt_no_padding( buffer.get(), buffer.get(), file_buffer_size );
    fwrite( buffer.get(), file_buffer_size, 1, output_file );
    bytes_to_decrypt -= file_buffer_size;
  }
  {//+
    fread( buffer.get(), 1, bytes_to_decrypt, input_file );
    size_t last = cbc.decrypt( buffer.get(), buffer.get(), bytes_to_decrypt );
    fwrite( buffer.get(), 1, last, output_file );
  }//-
  ///////////////////////////////////////Cleanup/////////////////////////////////////
  explicit_bzero( buffer.get(), file_buffer_size );
  fclose( input_file );
  fclose( output_file );
}

VGP::VGP(const int argc, const char * argv[])
{
  //Get a mapping of the c args
  Arg_Mapping args{ argc, argv };
  process_arg_mapping( args.get() );
  switch( _mode ) {
    //TODO
  }
}

void VGP::process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map)
{
  for( int i = 1; i < a_map.size(); ++i ) { // start counting @ 1 to skip the first arg (the name of the binary)
    /* Help Switch */
    if( a_map[i].first == "-h" || a_map[i].first == "--help" ) {
      print_help();
      exit( EXIT_SUCCESS );
    }
    /* Encrypt file switch */
    else if( a_map[i].first == "-e" || a_map[i].first == "--encrypt" ) {
      set_mode( Mode::Encrypt_File );
    }
    /* Decrypt file switch */
    else if( a_map[i].first == "-d" || a_map[i].first == "--decrypt" ) {
      set_mode( Mode::Decrypt_File );
    }
    /* Disallow floating arguments */
    else if( a_map[i].first.size() == 0 && a_map[i].second.size() != 0 ) {
      std::fprintf( stderr, "Error: Floating arguments ( %s ) not allowed.\n",
                    a_map[i].second.c_str() );
      exit( EXIT_FAILURE );
    }
    /* Assumed legal option-argument pair is stored */
    else {
      _option_argument_pairs.push_back( a_map[i] );
    }
  }///////////////////////////////////////////////
}

auto VGP::get_mode_c_str(const Mode m) const
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

void VGP::set_mode(const Mode m)
{
  if( _mode != Mode::None ) {
    std::fprintf( stderr, "Error: Mode %s already specified. May not specify another.\n\n",
                 get_mode_c_str( _mode ) );
    print_help();
    exit( EXIT_FAILURE );
  }
  _mode = a;
}

void VGP::print_help()
{
  std::puts(
    "Usage: vgp [Mode] [Switch...]\n"
    "Arguments to switches MUST be in seperate words. (i.e. vgp -e -i file; not vgp -e -ifile)\n"
    "Modes:\n"
    "-e, --encrypt\t\tSymmetric encryption mode; encrypt a file.\n"
    "-d, --decrypt\t\tSymmetric decryption mode; decrypt a file.\n"
    "Switches:\n"
    "-i, --input-file\t\tInput file; Must be specified for symmetric encryption and decryption modes.\n"
    "-o, --output-file\t\tOutput file; For symmetric encryption and decryption modes. Optional."
  );
}
