#include <ssc/files/files.hh>
#include "3crypt.hh"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef __gnu_linux__
    #error "Only gnu/linux implemented currently"
#endif


Threecrypt::Threecrypt(const int argc, const char * argv[])
{
    using namespace std;

    /* Get a mapping of the c args */
    Arg_Mapping args{ argc, argv };
    _process_arg_mapping( args.get() );
    switch( __mode ) {
        default:
            fprintf( stderr, "ERROR: No mode selected. (i.e. -e or -d)\n" );
            _print_help();
            exit( EXIT_FAILURE );
        case(Mode::Encrypt_File):
            _symmetric_encrypt_file();
            break;
        case(Mode::Decrypt_File):
            _symmetric_decrypt_file();
            break;
    }
}

void Threecrypt::_process_arg_mapping(const Arg_Mapping::Arg_Map_t & a_map)
{
    using namespace std;

    for ( int i = 1; i < a_map.size(); ++i ) { // start counting @ 1 to skip the first arg (the name of the binary)
        /* Help Switch */
        if ( a_map[i].first == "-h" ||
             a_map[i].first == "--help" )
        {
            _print_help();
            exit( EXIT_SUCCESS );
        }
        /* Encrypt file switch */
        else if ( a_map[i].first == "-e" ||
                  a_map[i].first == "--encrypt" )
        {
            _set_mode( Mode::Encrypt_File );
        }
        /* Decrypt file switch */
        else if ( a_map[i].first == "-d" ||
                  a_map[i].first == "--decrypt" )
        {
            _set_mode( Mode::Decrypt_File );
        }
        /* Disallow floating arguments */
        else if ( a_map[i].first.size()  == 0 &&
                  a_map[i].second.size() != 0 )
        {
            fprintf( stderr, "Error: Floating arguments ( %s ) not allowed.\n",
                        a_map[i].second.c_str() );
            exit( EXIT_FAILURE );
        }
        /* Assumed legal option-argument pair is stored */
        else
            __option_argument_pairs.push_back( a_map[i] );
    }///////////////////////////////////////////////
}

auto Threecrypt::_get_mode_c_str(const Mode m) const
    -> const char *
{
    switch ( m ) {
        default:
            return "Undefined_Mode";
        case(Mode::None):
            return "None";
        case(Mode::Encrypt_File):
            return "Encrypt_File";
        case(Mode::Decrypt_File):
            return "Decrypt_File";
    }
}

void Threecrypt::_set_mode(const Mode m)
{
    using namespace std;

    if ( __mode != Mode::None ) {
        fprintf( stderr, "Error: Mode %s already specified. May not specify another.\n\n",
         _get_mode_c_str( __mode ) );
        _print_help();
        exit( EXIT_FAILURE );
    }
    __mode = m;
}

void Threecrypt::_print_help() const
{
  std::puts(
    "\n"
    "Usage: 3crypt [Mode] [Switch...]\n"
    "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; not 3crypt -e -ifile)\n"
    "Modes:\n"
    "-e, --encrypt  Symmetric encryption mode; encrypt a file.\n"
    "-d, --decrypt  Symmetric decryption mode; decrypt a file.\n"
    "Switches:\n"
    "-i, --input-file  Input file; Must be specified for symmetric encryption and decryption modes.\n"
    "-o, --output-file Output file; For symmetric encryption and decryption modes. Optional for encryption"
  );
}

void Threecrypt::_symmetric_encrypt_file() const
{
    using namespace std;

    string input_filename, output_filename;
    /* Get the input and output filenames */
    for ( const auto & pair : __option_argument_pairs ) {
        check_file_name_sanity( pair.second, 1 );
        if      ( pair.first == "-i" ||
                  pair.first == "--input-file" )
        {
            input_filename = pair.second;
            if ( output_filename.size() == 0 )
                output_filename = input_filename + ".3c";
        }
        else if ( pair.first == "-o" ||
                  pair.first == "--output-file" )
        {
            output_filename = pair.second;
        }
        else {
            fprintf( stderr, "Error: unrecognizable switch %s\n", pair.first.c_str() );
            _print_help();
            exit( EXIT_FAILURE );
        }
    }

    /* Check filename sizes */
    if ( (input_filename.size()  == 0) ||
         (output_filename.size() == 0) )
    {
        fprintf( stderr, "Error: Either the input filename or the output filename has a length of zero.\n" );
        _print_help();
        exit( EXIT_FAILURE );
    }

    /* Open and map the files */
    struct File_Data f_data;
    _open_files( f_data, input_filename.c_str(), output_filename.c_str() );
    f_data.input_filesize  = get_file_size( f_data.input_fd );
    f_data.output_filesize = _calculate_post_encryption_size( f_data.input_filesize );
    _stretch_fd_to( f_data.output_fd, f_data.output_filesize );
    _map_files( f_data );
    /* Obtain the password */
    char password[ Max_Password_Length ];
    int password_length;
    {
        Terminal term{ false, false, true };
        term.get_password( password, Max_Password_Length );
        password_length = strlen( password );
    }
    /* Generate a header */
    CBC_V1_Header_t header;
    memset( header.id,                 0, sizeof(header.id) );
    memcpy( header.id, Threecrypt_CBC_V1, sizeof(header.id) );
    header.total_size = static_cast<uint64_t>( f_data.output_filesize );
    generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
    generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
    generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
    header.num_iter    =  1'250'000;
    header.num_concat  =  1'000'000;
    /* Copy header into new file */
    uint8_t * out = f_data.output_map;
    memcpy( out, &header, sizeof(header) );
    out += sizeof(header);
    /* Generate key */
    uint8_t derived_key[ Block_Bytes ];
    SSPKDF(
        derived_key,
        reinterpret_cast<const uint8_t *>( password ),
        password_length,
        header.sspkdf_salt,
        header.num_iter,
        header.num_concat
    );
    zero_sensitive( password, sizeof(password) );

    { /* Encrypt the file */
        CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
        size_t num = cbc.encrypt( f_data.input_map,
                                  out,
                                  f_data.input_filesize,
                                  header.cbc_iv );
        out += num;
    } 
    { /* MAC the file */
        Skein_t skein;
        skein.MAC( out,
                   f_data.output_map,
                   derived_key,
                   f_data.output_filesize - MAC_Bytes,
                   sizeof(derived_key),
                   MAC_Bytes );
    }

    _sync_map( f_data );    // Sync the mapping
    _unmap_files( f_data ); // Unmap files
    _close_files( f_data ); // Data cleanup
    explicit_bzero( derived_key, sizeof(derived_key) );
}

size_t Threecrypt::_calculate_post_encryption_size(const size_t pre_encr_size) const
{
    size_t s = pre_encr_size;
    if ( s < Block_Bytes ) // account for added padding (Block_Bytes)
        s = Block_Bytes;
    else
        s += ( Block_Bytes - (s % Block_Bytes));
    return s + sizeof(CBC_V1_Header_t) + MAC_Bytes; // account for header at the beginning of the file and the MAC at the end of the file
}

void Threecrypt::_stretch_fd_to(const int fd, const size_t size) const
{
    using namespace std;
    if ( ftruncate( fd, size ) == -1 ) {
        perror( "Failed to truncate file" );
        exit( EXIT_FAILURE );
    }
}

void Threecrypt::_symmetric_decrypt_file() const
{
    using namespace std;

    string input_filename, output_filename;
    /* Get the input and output filenames */
    for ( const auto & pair : __option_argument_pairs ) {
        check_file_name_sanity( pair.second, 1 );
        if ( pair.first == "-i" ||
             pair.first == "--input-file" )
        {
            input_filename = pair.second;
            if ( output_filename.size() == 0
                 && input_filename.size() >= 3 
                 && input_filename.substr( input_filename.size() - 3 ) == ".3c" )
            {
                output_filename = input_filename.substr( 0, input_filename.size() - 3 );
            }
        }
        else if ( pair.first == "-o" ||
                  pair.first == "--output-file" )
        {
            output_filename = pair.second;
        }
        else {
            fprintf( stderr, "Error: unrecognizable switch %s\n", pair.first.c_str() );
            _print_help();
            exit( EXIT_FAILURE );
        }
    }

    /* Check file sizes */
    if ( input_filename.size()  == 0 ||
         output_filename.size() == 0 )
    {
        fprintf( stderr, "Error: Either the input filename or the output filename has a length of zero.\n" );
        _print_help();
        exit( EXIT_FAILURE );
    }
    /* Open the files */
    struct File_Data f_data;
    _open_files( f_data, input_filename.c_str(), output_filename.c_str() );
    /* Get the sizes of the files */
    f_data.input_filesize  = get_file_size( f_data.input_fd );
    f_data.output_filesize = f_data.input_filesize;
    if ( f_data.input_filesize < (sizeof(CBC_V1_Header_t) + Block_Bytes + MAC_Bytes) ) {
        fprintf( stderr, "Error: Input file doesn't seem to be large enough to be a %s encrypted file\n",
                 Threecrypt_CBC_V1 );
        _close_files( f_data );
        remove( output_filename.c_str() );
        exit( EXIT_FAILURE );
    }
    _stretch_fd_to( f_data.output_fd, f_data.output_filesize );
    _map_files( f_data );
    /* Read the header out of the input file */
    const uint8_t * in = f_data.input_map;
    CBC_V1_Header_t header;
    memcpy( &header, in, sizeof(header) );
    in += sizeof(header);
    if ( memcmp( header.id, Threecrypt_CBC_V1, sizeof(Threecrypt_CBC_V1) - 1 ) != 0 ) {
        fprintf( stderr, "Error: The input file doesn't appear to be a %s encrypted file.\n", Threecrypt_CBC_V1 );
        _unmap_files( f_data );
        _close_files( f_data );
        remove( output_filename.c_str() );
        exit( EXIT_FAILURE );
    }
    if ( header.total_size != static_cast<uint64_t>(f_data.input_filesize) ) {
        fprintf( stderr, "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
        header.total_size, f_data.input_filesize );
        _unmap_files( f_data );
        _close_files( f_data );
        remove( output_filename.c_str() );
        exit( EXIT_FAILURE );
    }
    /* Obtain the password */
    char password[ Max_Password_Length ];
    int password_length;
    {
        Terminal term{ false, false, true };
        term.get_password( password, Max_Password_Length );
        password_length = strlen( password );
    }
    // Generate key
    uint8_t derived_key[ Block_Bytes ];
    SSPKDF( derived_key,
            reinterpret_cast<const uint8_t *>(password),
            password_length,
            header.sspkdf_salt,
            header.num_iter,
            header.num_concat );
    explicit_bzero( password, sizeof(password) );
    // Verify MAC
    {
        Skein_t skein;
        uint8_t gen_mac[ MAC_Bytes ];
        skein.MAC( gen_mac,
                   f_data.input_map,
                   derived_key,
                   f_data.input_filesize - MAC_Bytes,
                   sizeof(derived_key),
                   sizeof(gen_mac) );
        if ( memcmp( gen_mac, (f_data.input_map + f_data.input_filesize - MAC_Bytes), MAC_Bytes ) != 0 ) {
            fprintf( stderr, "Error: Authentication failed.\n"
                       "Possibilities: wrong password, the file is corrupted, or it has been somehow tampered with.\n" );
            _unmap_files( f_data );
            _close_files( f_data );
            remove( output_filename.c_str() );
            exit( EXIT_FAILURE );
        }
    }
    // Decrypt the file
    size_t plaintext_size;
    {
        CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
        plaintext_size = cbc.decrypt( in, f_data.output_map, f_data.input_filesize - (sizeof(CBC_V1_Header_t) + MAC_Bytes), header.cbc_iv );
    }
    _sync_map( f_data );
    _unmap_files( f_data );
    _stretch_fd_to( f_data.output_fd, plaintext_size );
    _close_files( f_data );
    explicit_bzero( derived_key, sizeof(derived_key) );
}

void Threecrypt::_open_files(struct File_Data & f_data,
                      const char * const input_filename,
                      const char * const output_filename) const
{
    using namespace std;

    if ( ! file_exists( input_filename ) ) {
        fprintf( stderr, "Error: input file '%s' doesn't seem to exist.\n", input_filename );
        exit( EXIT_FAILURE );
    }
    if ( file_exists( output_filename ) ) {
        fprintf( stderr, "Error: output file '%s' already seems to exist.\n", output_filename );
        exit( EXIT_FAILURE );
    }

    f_data.input_fd  = open( input_filename, (O_RDWR | O_CREAT), static_cast<mode_t>(0600) );
    if ( f_data.input_fd == -1 ) {
        fprintf( stderr, "Error: Unable to open input file '%s'\n", input_filename );
        exit( EXIT_FAILURE );
    }
    f_data.output_fd = open( output_filename, (O_RDWR | O_CREAT | O_TRUNC), static_cast<mode_t>(0600) );
    if ( f_data.output_fd == -1 ) {
        fprintf( stderr, "Error: Unable to open output file '%s'\n", output_filename );
        exit( EXIT_FAILURE );
    }

}

void Threecrypt::_close_files(struct File_Data & f_data) const
{
    using namespace std;

    if ( close( f_data.input_fd ) == -1 ) {
        perror( "Error: was not able to close input file" );
        exit( EXIT_FAILURE );
    }
    if ( close( f_data.output_fd ) == -1 ) {
        perror( "Error: was not able to close output file" );
        exit( EXIT_FAILURE );
    }
}

void Threecrypt::_map_files(struct File_Data & f_data) const
{
    using namespace std;

    f_data.input_map = reinterpret_cast<uint8_t *>(mmap( 0, f_data.input_filesize, PROT_READ, MAP_SHARED, f_data.input_fd, 0 ));
    if ( f_data.input_map == MAP_FAILED ) {
        perror( "Failed to open input map" );
        exit( EXIT_FAILURE );
    }
    f_data.output_map = reinterpret_cast<uint8_t *>(mmap( 0, f_data.output_filesize, PROT_READ|PROT_WRITE, MAP_SHARED, f_data.output_fd, 0 ));
    if ( f_data.output_map == MAP_FAILED ) {
        perror( "Failed to open output map" );
        exit( EXIT_FAILURE );
    }
}

void Threecrypt::_unmap_files(struct File_Data & f_data) const
{
    using namespace std;

    if ( munmap( f_data.input_map, f_data.input_filesize ) == -1 ) {
        fprintf( stderr, "Error: Failed to unmap input file\n" );
        exit( EXIT_FAILURE );
    }
    if ( munmap( f_data.output_map, f_data.output_filesize ) == -1 ) {
        fprintf( stderr, "Error: Failed to unmap output file\n" );
        exit( EXIT_FAILURE );
    }
}

void Threecrypt::_sync_map(struct File_Data & f_data) const
{
    using namespace std;

    if ( msync( f_data.output_map, f_data.output_filesize, MS_SYNC ) == -1 ) {
        fprintf( stderr, "Error: Failed to sync mmap()\n" );
        _unmap_files( f_data );
        _close_files( f_data );
        exit( EXIT_FAILURE );
    }
}
