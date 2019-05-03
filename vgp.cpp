#include "include/files/files.hpp"
#include "vgp.hpp"
#include <unistd.h>

VGP::VGP(const int argc, const char * argv[])
{
  //Get a mapping of the c args
  Arg_Mapping args{ argc, argv };
  process_arg_mapping( args.get() );
  switch( _mode ) {
    default:
      std::fprintf( stderr,
          "ERROR: No mode selected. (i.e. -e or -d)\n"
      );
      print_help();
      std::exit( 1 );
    case( Mode::Encrypt_File ):
      symmetric_encrypt_file();
      break;
    case( Mode::Decrypt_File ):
      break;
  }
}

void VGP::process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map)
{
  for( int i = 1; i < a_map.size(); ++i ) { // start counting @ 1 to skip the first arg (the name of the binary)
    /* Help Switch */
    if( a_map[i].first == "-h" || a_map[i].first == "--help" ) {
      print_help();
      std::exit( EXIT_SUCCESS );
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
      std::exit( EXIT_FAILURE );
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
    std::exit( EXIT_FAILURE );
  }
  _mode = m;
}

void VGP::print_help()
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

void VGP::symmetric_encrypt_file() const
{
  std::string input_filename, output_filename;
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
  }
}
