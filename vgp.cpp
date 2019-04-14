#include "include/files/files.hpp"
#include "vgp.hpp"

void VGP::cbc_encrypt_file(const char * const input_filename, const char * const output_filename,
                           const uint8_t * const key, const uint8_t * const iv) const
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
  cbc_t cbc{ ThreeFish<512>{ reinterpret_cast<const uint64_t*>(key) } }; // feed key
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
  const size_t input_file_size = get_file_size( input_file );           // see how big the file is
  uint8_t buffer[ Block_Bytes * 2 ];                 // Make the buffer 2 blocks wide, to accomodate for padding at the end.
  //Write the IV into the beginning of the file.
  fwrite( iv, 1, Block_Bytes, output_file );

  //Encrypt up to the the last block
  const size_t last_input_block_offset = (input_file_size > Block_Bytes) ? (input_file_size - Block_Bytes) : 0; // offset of the final block
  cbc.manually_set_state( iv ); // set the iv
  for( size_t in_off = 0; in_off < last_input_block_offset; in_off += Block_Bytes ) { // iterate over all blocks except the last
    fread( buffer, 1, sizeof(buffer), input_file );   // get 512 bits (64 bytes) from file into buffer
    cbc.encrypt_no_padding( buffer, buffer, Block_Bytes );   // encrypt those 64 bytes
    fwrite( buffer, 1, sizeof(buffer), output_file ); // write the encryptd 64 bytes to output_file
  }
  //Encrypt the last block with padding
  {//+
    fread( buffer, 1, input_file_size - last_input_block_offset, input_file );
    size_t last_block = cbc.encrypt( buffer, buffer, input_file_size - last_input_block_offset ); // encrypts the last block: minimum 1, maximum 2 blocks
    fwrite( buffer, 1, last_block, output_file ); //
  }//-
  //Cleanup
  explicit_bzero( buffer, sizeof(buffer) );
  fclose( input_file );
  fclose( output_file );
}

void VGP::cbc_decrypt_file(const char * const input_filename, const char * const output_filename, const uint8_t * const key) const
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

  //Open the input file and the output file
  cbc_t cbc{ ThreeFish<512>{ reinterpret_cast<const uint64_t*>(key) } };
  FILE * const input_file = fopen( input_filename, "rb" ); // open the input file
  FILE * const output_file = fopen( output_filename, "wb" ); // open the output file
  //Check if files successfully opened
  if constexpr( Debug ) {
    if( (input_file == nullptr) || (output_file == nullptr) ) {
      fprintf( stderr, "Failed to open input file or output file\n"
                       "Input file is: %p\n"
                       "Output file is: %p\n", input_file, output_file );
    }
  }
  const size_t input_file_size = get_file_size( input_file ); // get the size of the input file
  //Check if the file is the right size to be decrypted
  if( input_file_size % Block_Bytes != 0 ) {
    fprintf( stderr, "The input file does not appear to be the right size to be decrypted.\n"
                     "The file was %zu bytes.\n", input_file_size );
    exit( 1 );
  }
  //Get the initialization vector
  if( iv != nullptr )
    cbc.manually_set_state( iv );
  else {
    uint8_t file_iv[ Block_Bytes ];
    fread( file_iv, 1, sizeof(file_iv), input_file );
    cbc.manually_set_state( file_iv );
  }
  //Decrypt up to the last block
  uint8_t buffer[ Block_Bytes ];
  const size_t last_input_block_offset = input_file_size - Block_Bytes;
  for( size_t b_off = 0; b_off < last_input_block_offset; b_off += Block_Bytes ) {
    fread( buffer, 1, sizeof(buffer), input_file );
    cbc.decrypt_no_padding( buffer, buffer, sizeof(buffer) );
    fwrite( buffer, 1, sizeof(buffer), output_file );
  }
  //Decrypt last block with padding
  {//+
    fread( buffer, 1, sizeof(buffer), input_file );
    size_t last_block = cbc.decrypt( buffer, buffer, sizeof(buffer) );
    fwrite( buffer, 1, sizeof(buffer), output_file );
  }//-
  //Cleanup
  explicit_bzero( buffer, sizeof(buffer) );
  fclose( input_file );
  fclose( output_file );
}






