#include "include/files/files.hpp"
#include "vgp.hpp"
#include <unistd.h>

void VGP::cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                           const uint8_t * const key, const uint8_t * const iv,
                           const size_t file_buffer_size) const
{
  using namespace std;
  //Validate arguments somewhat
  if constexpr( Debug ) {
    {//+
      if( (key == nullptr) || (iv == nullptr) ) { // Diallow key or iv from being nullptr. That wouldn't make sense.
        fprintf( stderr, "ERROR: VGP::encrypt_file -- Either the key or the initialization vector was a nullptr\n"
                         "The Key: %p\n"
                         "The IV : %p\n", key, iv );
        exit( 1 );
      }
    }//-
  }

  //Open the input file, and the file to write to.
  cbc_t cbc{ Threefish_t{ reinterpret_cast<const uint64_t*>(key) } }; // feed key
  cbc.manually_set_state( iv );                // & iv into the cbc_t object
  FILE * const input_file = fopen ( input_filename , "rb" );   // open the input file
  FILE * const output_file = fopen( output_filename, "wb" ); // open the output file
  //Check if files successfully opened
  if constexpr( Debug ) {
    if( (input_file == nullptr) || (output_file == nullptr) ) {
      fprintf( stderr, "Failed to open input file or output file\n"
                       "Input file is: %p\n"
                       "Output file is: %p\n", input_file, output_file );
      exit( 1 );
    }
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
                           const size_t file_buffer_size) const
{
  using namespace std;


  //Validate arguments somewhat
  if constexpr( Debug ) {
    {//+
      if( (key == nullptr) ) { // Diallow key from being nullptr. That wouldn't make sense.
        fprintf( stderr, "ERROR: VGP::encrypt_file -- Either the key or the initialization vector was a nullptr\n"
                         "The Key: %p\n", key );
        exit( 1 );
      }
    }//-
  }

  //Open the input file and the output file
  cbc_t cbc{ Threefish_t{ reinterpret_cast<const uint64_t*>(key) } };
  FILE * const input_file = fopen( input_filename, "rb" ); // open the input file
  FILE * const output_file = fopen( output_filename, "wb" ); // open the output file
  //Check if files successfully opened
  if constexpr( Debug ) {
    if( (input_file == nullptr) || (output_file == nullptr) ) {
      fprintf( stderr, "Failed to open input file or output file\n"
                       "Input file is: %p\n"
                       "Output file is: %p\n", input_file, output_file );
      exit( 1 );
    }
  }
  size_t bytes_to_decrypt = get_file_size( input_file );
  if( bytes_to_decrypt < (Block_Bytes * 2) ) {
    fprintf( stderr, "Error: The input file does not appear to be big enough to have been Threefish-512-CBC encrypted.\n" );
    exit( 1 );
  }
  if( (bytes_to_decrypt % Block_Bytes) != 0 ) {
    fprintf( stderr, "Error: The input files does not appear to be a multiple of Threefish-512-CBC encrypted blocks.\n" );
    exit( 1 );
  }
  if( (file_buffer_size % Block_Bytes) != 0 ) {
    fprintf( stderr, "Error: The file buffer size must be a multiple of 64-bytes.\n" );
    exit( 1 );
  }
  //Get the initialization vector
  {//+
    uint8_t file_iv[ Block_Bytes ];
    bytes_to_decrypt -= fread( file_iv, 1, sizeof(file_iv), input_file );
    cbc.manually_set_state( file_iv );
  }//-
  //Decrypt
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
  //Cleanup
  explicit_bzero( buffer.get(), file_buffer_size );
  fclose( input_file );
  fclose( output_file );
}

void VGP::generate_random_bytes(uint8_t * const buffer, size_t num_bytes)
{
  size_t offset = 0;
  while( num_bytes >= 256 ) {
    getentropy( (buffer + offset), 256 );
    num_bytes -= 256;
    offset += 256;
  }
  getentropy( (buffer + offset), num_bytes );
}






