#include "3crypt.hh"

#if   defined(__gnu_linux__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <unistd.h>
#elif defined(_WIN64)
#else
    #error "3crypt.cc only defined for Gnu/Linux and MS Windows"
#endif

namespace threecrypt
{
    void open_files(File_Data & f_data, char const *input_filename, char const *output_filename)
    {
        using namespace std;
        ssc::enforce_file_existence( input_filename , true  );
        ssc::enforce_file_existence( output_filename, false );

#if   defined(__gnu_linux__)
        if ( (f_data.input_fd = open( input_filename, (O_RDWR|O_CREAT), static_cast<mode_t>(0600) )) == -1 ) {
            fprintf( stderr, "Error: Unable to open input file '%s'\n", input_filename );
            exit( EXIT_FAILURE );
        }
        if ( (f_data.output_fd = open( output_filename, (O_RDWR|O_CREAT|O_TRUNC), static_cast<mode_t>(0600) )) == -1 ) {
            fprintf( stderr, "Error: Unable to open output file '%s'\n", output_filename );
            exit( EXIT_FAILURE );
        }
#elif defined(_WIN64)
        /* CreateFileA( LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
         *              DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile ) */
        {
            auto handle = CreateFileA( input_filename, (GENERIC_READ), 0,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                       NULL );
            if ( handle == INVALID_HANDLE_VALUE ) {
                fprintf( stderr, "Error: Unable to open input file '%s'\n", input_filename );
                exit( EXIT_FAILURE );
            }
            f_data.input_handle = handle;
        }
        {
            auto handle = CreateFileA( output_filename, (GENERIC_READ|GENERIC_WRITE), 0,
                                       NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                       NULL );
            if ( handle == INVALID_HANDLE_VALUE ) {
                fprintf( stderr, "Error: Unable to open output file '%s'\n", output_filename );
                exit( EXIT_FAILURE );
            }
            f_data.output_handle = handle;
        }
#else
    #error "threecrypt::open_files only defined for Gnu/Linux and MS Windows"
#endif
    }/*! open_files(File_Data &file_data, char const *input_filename, char const *output_filename) */
    void close_files(File_Data const & f_data)
    {
        using namespace std;
#if   defined(__gnu_linux__)
        if ( close( f_data.input_fd ) == -1 ) {
            perror( "Error: was not able to close input file descriptor" );
            exit( EXIT_FAILURE );
        }
        if ( close( f_data.output_fd ) == -1 ) {
            perror( "Error: was not able to close output file descriptor" );
            exit( EXIT_FAILURE );
        }
#elif defined(_WIN64)
        if ( CloseHandle( f_data.input_handle ) == 0 ) {
            fputs( "Error: was not able to close input file handle\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( CloseHandle( f_data.output_handle ) == 0 ) {
            fputs( "Error: was not able to close output file handle\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "threecrypt::close_files only defined for Gnu/Linux and MS Windows"
#endif
    }/*! close_files(File_Data const & f_data) */
    void map_files(File_Data & f_data)
    {
        using namespace std;
#if   defined(__gnu_linux__)
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
#elif defined(_WIN64)
        /* HANDLE CreateFileMappingA( HANDLE                hFile,
         *                            LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
         *                            DWORD                 flProtect,
         *                            DWORD                 dwMaximumSizeHigh,
         *                            DWORD                 dwMaximumSizeLow,
         *                            LPCSTR                lpName );
         */
        {// Get a FileMapping object for the input file
            DWORD high_bits = static_cast<DWORD>(f_data.input_filesize >> 32);
            DWORD low_bits  = static_cast<DWORD>(f_data.input_filesize);
            auto file_mapping = CreateFileMappingA( f_data.input_handle,
                                                    NULL,
                                                    PAGE_READONLY,
                                                    high_bits,
                                                    low_bits,
                                                    NULL );
            if ( file_mapping == NULL ) {
                fputs( "Error: Unable to memory-map input file\n", stderr );
                exit( EXIT_FAILURE );
            }
            f_data.input_filemapping = file_mapping;
        }
        {// Get a FileMapping object for the output file
            DWORD high_bits = static_cast<DWORD>(f_data.output_filesize >> 32);
            DWORD low_bits  = static_cast<DWORD>(f_data.output_filesize);
            auto file_mapping = CreateFileMappingA( f_data.output_handle,
                                                    NULL,
                                                    PAGE_READWRITE,
                                                    high_bits,
                                                    low_bits,
                                                    NULL );
            if ( file_mapping == NULL ) {
                fputs( "Error: Unable to memory-map output file\n", stderr );
                exit( EXIT_FAILURE );
            }
            f_data.output_filemapping = file_mapping;
        }
        {// MapViewOfFile for input file
            auto view = MapViewOfFile( f_data.input_filemapping,
                                       FILE_MAP_READ,
                                       //TODO
        }
        {// MapViewOfFile for output file
        }
#else
    #error "threecrypt::map_files only defined for Gnu/Linux and MS Windows"
#endif
    }
#if ! defined(__gnu_linux__)
    #error "unmap_files currently only implemented for Gnu/Linux"
#endif
    void unmap_files(File_Data const & f_data)
    {
        using namespace std;
        if ( munmap( f_data.input_map, f_data.input_filesize ) == -1 ) {
            perror( "Failed to unmap input file" );
            exit( EXIT_FAILURE );
        }
        if ( munmap( f_data.output_map, f_data.output_filesize ) == -1 ) {
            perror( "Failed to unmap output file" );
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
            fputs( "Error: Failed to sync mmap()\n", stderr );
            unmap_files( f_data );
            close_files( f_data );
            exit( EXIT_FAILURE );
        }
    }
#ifdef __gnu_linux__
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
