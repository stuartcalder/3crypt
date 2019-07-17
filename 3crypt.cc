#include "3crypt.hh"

namespace threecrypt
{
    void print_help()
    {
        std::puts( "Usage: 3crypt [Mode] [Switch...]\n"
                   "Arguments to switches MUST be in seperate words. (i.e. 3crypt -e -i file; not 3crypt -e -ifile)\n"
                   "Modes:\n"
                   "-e, --encrypt  Symmetric encryption mode; encrypt a file using a passphrase.\n"
                   "-d, --decrypt  Symmetric decryption mode; decrypt a file using a passphrase.\n"
                   "Switches:\n"
                   "-i, --input-file  Input file ; Must be specified for symmetric encryption and decryption modes.\n"
                   "-o, --output-file Output file; For symmetric encryption and decryption modes. Optional for encryption." );
    }
#if ! defined(__gnu_linux__)
    #error "open_files currently only implemented for Gnu/Linux"
#endif
    void open_files(File_Data & f_data, char const *input_filename, char const *output_filename)
    {
        using namespace std;
        ssc::enforce_file_existence( input_filename , true  );
        ssc::enforce_file_existence( output_filename, false );

        f_data.input_fd = open( input_filename, (O_RDWR | O_CREAT), static_cast<mode_t>(0600) );
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
#if ! defined(__gnu_linux__)
    #error "close_files currently only implemented for Gnu/Linux"
#endif
    void close_files(File_Data const & f_data)
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
#if ! defined(__gnu_linux__)
    #error "map_files currently only implemented for Gnu/Linux"
#endif
    void map_files(File_Data & f_data)
    {
        using namespace std;
        f_data.input_map = reinterpret_cast<u8_t *>(mmap( 0, f_data.input_filesize, PROT_READ, MAP_SHARED, f_data.input_fd, 0 ));
        if ( f_data.input_map == MAP_FAILED ) {
            perror( "Failed to open input map" );
            exit( EXIT_FAILURE );
        }
        f_data.output_map = reinterpret_cast<u8_t *>(mmap( 0, f_data.output_filesize, PROT_READ|PROT_WRITE, MAP_SHARED, f_data.output_fd, 0 ));
        if ( f_data.output_map == MAP_FAILED ) {
            perror( "Failed to open output map" );
            exit( EXIT_FAILURE );
        }
    }
#if ! defined(__gnu_linux__)
    #error "unmap_files currently only implemented for Gnu/Linux"
#endif
    void unmap_files(File_Data const & f_data)
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
#if ! defined(__gnu_linux__)
    #error "sync_map currently only implemented for Gnu/Linux"
#endif
    void sync_map(File_Data const & f_data)
    {
        using namespace std;
        if ( msync( f_data.output_map, f_data.output_filesize, MS_SYNC ) == -1 ) {
            fprintf( stderr, "Error: Failed to sync mmap()\n" );
            unmap_files( f_data );
            close_files( f_data );
            exit( EXIT_FAILURE );
        }
    }
#if defined(__gnu_linux__)
    void set_file_size(int const file_d, size_t const new_size)
    {
        using namespace std;
        if ( ftruncate( file_d, new_size ) == -1 ) {
            perror( "Failed to set file size" );
            exit( EXIT_FAILURE );
        }
    }
#endif
#if ! defined(__gnu_linux__)
    #error "set_file_size currently only implemented for Gnu/Linux"
#endif
    void set_file_size(char const *filename, size_t const new_size)
    {
        if ( truncate( filename, new_size ) == -1 ) {
            perror( "Failed to set file size" );
            exit( EXIT_FAILURE );
        }
    }

} /* ! namespace threecrypt */
