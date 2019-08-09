#include "3crypt.hh"

#if !(defined( __gnu_linux__ ) || defined( _WIN64 ))
    #error "3crypt.cc only defined for Gnu/Linux and 64-bit MS Windows"
#endif

namespace threecrypt
{
    void open_files(File_Data & f_data, char const * __restrict input_filename, char const * __restrict output_filename)
    {
        using namespace std;
        ssc::enforce_file_existence( input_filename , true  );
        ssc::enforce_file_existence( output_filename, false );

#if defined( __gnu_linux__ )
        if ( (f_data.input_fd = open( input_filename, (O_RDWR|O_CREAT), static_cast<mode_t>(0600) )) == -1 )
        {
            fprintf( stderr, "Error: Unable to open input file '%s'\n", input_filename );
            exit( EXIT_FAILURE );
        }
        if ( (f_data.output_fd = open( output_filename, (O_RDWR|O_CREAT|O_TRUNC), static_cast<mode_t>(0600) )) == -1 )
        {
            fprintf( stderr, "Error: Unable to open output file '%s'\n", output_filename );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        /* CreateFileA( LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
         *              DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile ) */
        {
            auto handle = CreateFileA( input_filename, (GENERIC_READ), 0,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                       NULL );
            if ( handle == INVALID_HANDLE_VALUE )
            {
                fprintf( stderr, "Error: Unable to open input file '%s'\n", input_filename );
                exit( EXIT_FAILURE );
            }
            f_data.input_handle = handle;
        }
        {
            auto handle = CreateFileA( output_filename, (GENERIC_READ|GENERIC_WRITE), 0,
                                       NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                       NULL );
            if ( handle == INVALID_HANDLE_VALUE )
            {
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
#if   defined( __gnu_linux__ )
        if ( close( f_data.input_fd ) == -1 )
        {
            fputs( "Error: was not able to close input file descriptor\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( close( f_data.output_fd ) == -1 )
        {
            fputs( "Error: was not able to close output file descriptor\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( CloseHandle( f_data.input_handle ) == 0 )
        {
            fputs( "Error: was not able to close input file handle\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( CloseHandle( f_data.output_handle ) == 0 )
        {
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
#if   defined( __gnu_linux__ )
        f_data.input_map = reinterpret_cast<u8_t *>(mmap( 0, f_data.input_filesize, PROT_READ, MAP_SHARED, f_data.input_fd, 0 ));
        if ( f_data.input_map == MAP_FAILED )
        {
            fputs( "Error: Failed to open input map\n", stderr );
            exit( EXIT_FAILURE );
        }
        f_data.output_map = reinterpret_cast<u8_t *>(mmap( 0, f_data.output_filesize, PROT_READ|PROT_WRITE, MAP_SHARED, f_data.output_fd, 0 ));
        if ( f_data.output_map == MAP_FAILED )
        {
            fputs( "Error: Failed to open output map\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
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
            if ( file_mapping == NULL )
            {
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
            if ( file_mapping == NULL )
            {
                fputs( "Error: Unable to memory-map output file\n", stderr );
                exit( EXIT_FAILURE );
            }
            f_data.output_filemapping = file_mapping;
        }
        {// MapViewOfFile for input file
            f_data.input_map = static_cast<u8_t *>(MapViewOfFile( f_data.input_filemapping,
                                                   FILE_MAP_READ,
                                                   0,
                                                   0,
                                                   f_data.input_filesize ));
            if ( f_data.input_map == NULL )
            {
                fputs( "Error: Failed to MapViewOfFile for the input file\n", stderr );
                exit( EXIT_FAILURE );
            }
        }
        {// MapViewOfFile for output file
            f_data.output_map = static_cast<u8_t *>(MapViewOfFile( f_data.output_filemapping,
                                                    (FILE_MAP_READ|FILE_MAP_WRITE),
                                                    0,
                                                    0,
                                                    f_data.output_filesize ));
            if ( f_data.output_map == NULL )
            {
                fputs( "Error: Failed to MapViewOfFile for the output file\n", stderr );
                exit( EXIT_FAILURE );
            }
        }
#else
    #error "threecrypt::map_files only defined for Gnu/Linux and MS Windows"
#endif
    }/* ! map_files(File_Data & f_data) */
    void unmap_files(File_Data const & f_data)
    {
        using namespace std;
#if defined( __gnu_linux__ )
        if ( munmap( f_data.input_map, f_data.input_filesize ) == -1 )
        {
            fputs( "Error: Failed to unmap input file\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( munmap( f_data.output_map, f_data.output_filesize ) == -1 )
        {
            fputs( "Error: Failed to unmap input file\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( UnmapViewOfFile( static_cast<LPCVOID>(f_data.input_map) ) == 0 )
        {
            fputs( "Error: Failed to unmap the input file\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( UnmapViewOfFile( static_cast<LPCVOID>(f_data.output_map) ) == 0 )
        {
            fputs( "Error: Failed to unmap the output file\n", stderr );
            exit( EXIT_FAILURE );
        }
#if 1
        if ( CloseHandle( f_data.input_filemapping ) == 0 )
        {
            fputs( "Error: was not able to close input filemapping\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( CloseHandle( f_data.output_filemapping) == 0 )
        {
            fputs( "Error: was not able to close output filemapping\n", stderr );
            exit( EXIT_FAILURE );
        }
#endif
#else
    #error "threecrypt::unmap_files only defined for Gnu/Linux and MS Windows"
#endif
    }/* ! unmap_files(File_Data const &f_data) */
    void sync_map(File_Data const & f_data)
    {
        using namespace std;
#if defined( __gnu_linux__ )
        if ( msync( f_data.output_map, f_data.output_filesize, MS_SYNC ) == -1 )
        {
            fputs( "Error: Failed to sync mmap()\n", stderr );
            unmap_files( f_data );
            close_files( f_data );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( FlushViewOfFile( static_cast<LPCVOID>(f_data.output_map), f_data.output_filesize ) == 0 )
        {
            fputs( "Error: Failed to FlushViewOfFile()\n", stderr );
            unmap_files( f_data );
            close_files( f_data );
            exit( EXIT_FAILURE );
        }
#else
    #error "threecrypt::sync_map currently only implemented for Gnu/Linux and MS Windows"
#endif
    }/* ! sync_map(File_Data const &) */
#if   defined( __gnu_linux__ )
    void set_file_size(int const file_d, size_t const new_size)
    {
        using namespace std;
        if ( ftruncate( file_d, new_size ) == -1 )
        {
            fputs( "Error: Failed to set file size\n", stderr );
            exit( EXIT_FAILURE );
        }
    }
#elif defined( _WIN64 )
    void set_file_size(HANDLE handle, size_t const new_size)
    {
        using namespace std;

        LARGE_INTEGER l_i;
        l_i.QuadPart = static_cast<decltype(l_i.QuadPart)>(new_size);
        // Move the file pointer to the desired offset from the beginning of the file
        if ( SetFilePointerEx( handle, l_i, NULL, FILE_BEGIN ) == 0 )
        {
            fputs( "Failed to SetFilePointerEx()\n", stderr );
            exit( EXIT_FAILURE );
        }
        // Truncate the file here
        if ( SetEndOfFile( handle ) == 0 )
        {
            fputs( "Failed to SetEndOfFile()\n", stderr );
            auto last_error = GetLastError();
            fprintf( stderr, "Last error code was %d\n", last_error );
            exit( EXIT_FAILURE );
        }
    }
#endif
    void set_file_size(char const *filename, size_t const new_size)
    {
        using namespace std;
#if defined( __gnu_linux__ )
        if ( truncate( filename, new_size ) == -1 )
        {
            fputs( "Error: Failed to set file size\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
        fputs( "ERROR: set_file_size(char const *filename, size_t const new_size) only defined for Gnu/Linux\n", stderr );
        exit( EXIT_FAILURE );
#endif
    }/* ! set_file_size */

} /* ! namespace threecrypt */
