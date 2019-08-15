#include "3crypt.hh"

#if !( defined( __gnu_linux__ ) || defined( _WIN64 ) )
    #error "3crypt.cc only defined for Gnu/Linux and 64-bit MS Windows"
#endif

namespace threecrypt
{
    OS_File_t open_file_existing(char const * filename, bool const readonly)
    {
        using namespace std;
        ssc::enforce_file_existence( filename, true );
#if   defined( __gnu_linux__ )
        int file_fd;
        decltype(O_RDWR) read_write_rights;
        
        if ( readonly )
            read_write_rights = O_RDONLY;
        else
            read_write_rights = O_RDWR;
        if ( (file_fd = open( filename, read_write_rights, static_cast<mode_t>(0600) )) == -1 )
        {
            perror( "Unable to open file" );
            exit( EXIT_FAILURE );
        }
        return file_fd;
#elif defined( _WIN64 )
        HANDLE file_handle;
        decltype(GENERIC_READ) read_write_rights;

        if ( readonly )
            read_write_rights = GENERIC_READ;
        else
            read_write_rights = (GENERIC_READ|GENERIC_WRITE);
        if ( (file_handle = CreateFileA( filename, read_write_rights, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL )) == INVALID_HANDLE_VALUE )
        {
            fprintf( stderr, "Error: Unable to open file %s.\n", filename );
            exit( EXIT_FAILURE );
        }
        return file_handle;
#else
    #error "open_file_existing only defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! open_file_existing */
    OS_File_t create_new_file(char const * filename)
    {
        using namespace std;
        ssc::enforce_file_existence( filename, false );
#if   defined( __gnu_linux__ )
        int file_fd;
        if ( (file_fd = open( filename, (O_RDWR|O_TRUNC|O_CREAT), static_cast<mode_t>(0600) )) == 1 )
        {
            perror( "Unable to create file" );
            exit( EXIT_FAILURE );
        }
        return file_fd;
#elif defined( _WIN64 )
        HANDLE file_handle;
        if ( (file_handle = CreateFileA( filename, (GENERIC_READ|GENERIC_WRITE), 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL )) == INVALID_HANDLE_VALUE )
        {
            fprintf( stderr, "Error: Unable to create file %s.\n", filename );
            exit( EXIT_FAILURE );
        }
        return file_handle;
#else
    #error "create_new_file only defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! create_new_file */
    void close_file(OS_File_t const os_file)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( close( os_file ) == 1 )
        {
            perror( "Was not able to close file descriptor" );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( CloseHandle( os_file ) == 0 )
        {
            fputs( "Error: was not able to close file descriptor\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "close_file only defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! close_File */
    void map_file(OS_Map & os_map, bool const readonly)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        decltype(PROT_READ) readwrite_flag;
        if ( readonly )
            readwrite_flag = PROT_READ;
        else
            readwrite_flag = (PROT_READ|PROT_WRITE);
        os_map.ptr = reinterpret_cast<u8_t *>(mmap( 0, os_map.size, readwrite_flag, MAP_SHARED, os_map.os_file, 0 ));
        if ( os_map.ptr == MAP_FAILED )
        {
            perror( "Failed to open map" );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        decltype(PAGE_READONLY) page_readwrite_flag;
        decltype(FILE_MAP_READ) map_readwrite_flag;
        if ( readonly )
        {
            page_readwrite_flag = PAGE_READONLY;
            map_readwrite_flag = FILE_MAP_READ;
        }
        else
        {
            page_readwrite_flag = PAGE_READWRITE;
            map_readwrite_flag  = (FILE_MAP_READ|FILE_MAP_WRITE);
        }

        DWORD high_bits = static_cast<DWORD>( os_map.size >> 32 );
        DWORD low_bits  = static_cast<DWORD>( os_map.size );
        os_map.win64_filemapping = CreateFileMappingA( os_map.os_file, NULL, page_readwrite_flag,
                                                       high_bits, low_bits, NULL );
        if ( os_map.win64_filemapping == NULL )
        {
            fputs( "Error: Unable to memory-map file\n", stderr );
            exit( EXIT_FAILURE );
        }
        os_map.ptr = static_cast<u8_t *>(MapViewOfFile( os_map.win64_filemapping, map_readwrite_flag, 0, 0, os_map.size ));
        if ( os_map.ptr == NULL )
        {
            fputs( "Error: Failed to MapViewOfFile\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "map_file only defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! map_file */
    void open_files(File_Data & f_data, char const * __restrict input_filename, char const * __restrict output_filename)
    {
        using namespace std;
        f_data.input_map.os_file  = open_file_existing( input_filename, true );
        f_data.output_map.os_file = create_new_file( output_filename );
#if 0
        using namespace std;
        ssc::enforce_file_existence( input_filename , true  );
        ssc::enforce_file_existence( output_filename, false );

#if defined( __gnu_linux__ )
        if ( (f_data.input_fd = open( input_filename, (O_RDWR), static_cast<mode_t>(0600) )) == -1 )
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
            auto handle = CreateFileA( input_filename, (GENERIC_READ|GENERIC_WRITE), 0,
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
    #error "threecrypt::open_files only defined for Gnu/Linux and 64-bit MS Windows"
#endif
#endif
    }/*! open_files(File_Data &file_data, char const *input_filename, char const *output_filename) */
    void close_files(File_Data const & f_data)
    {
        using namespace std;
        close_file( f_data.input_map.os_file );
        close_file( f_data.output_map.os_file );
#if 0
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
    #error "threecrypt::close_files only defined for Gnu/Linux and 64-bit MS Windows"
#endif
#endif
    }/*! close_files(File_Data const & f_data) */
    void unmap_file(OS_Map const & os_map)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( munmap( os_map.ptr, os_map.size ) == -1 )
        {
            perror( "Failed to unmap file" );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( UnmapViewOfFile( static_cast<LPCVOID>(os_map.ptr) ) == 0 )
        {
            fputs( "Error: Failed to unmap the file\n", stderr );
            exit( EXIT_FAILURE );
        }
        close_file( os_map.win64_filemapping );
#else
    #error "unmap_file only defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! unmap_file */
    void synchronize_map(OS_Map const & os_map)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( msync( os_map.ptr, os_map.size, MS_SYNC ) == -1 )
        {
            perror( "Failed to sync mmap()" );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( FlushViewOfFile( static_cast<LPCVOID>(os_map.ptr), os_map.size ) == 0 )
        {
            fputs( "Error: Failed to FlushViewOfFile()\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "synchronize_map defined for Gnu/Linux and 64-bit MS Windows"
#endif
    }/* ! synchronize_map */
    void map_files(File_Data & f_data)
    {
        using namespace std;
        map_file( f_data.input_map, true );
        map_file( f_data.output_map, false );
#if 0
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
    #error "threecrypt::map_files only defined for Gnu/Linux and 64-bit MS Windows"
#endif
#endif
    }/* ! map_files(File_Data & f_data) */
    void unmap_files(File_Data const & f_data)
    {
        using namespace std;
        unmap_file( f_data.input_map );
        unmap_file( f_data.output_map );
#if 0
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
#else
    #error "threecrypt::unmap_files only defined for Gnu/Linux and 64-bit MS Windows"
#endif
#endif
    }/* ! unmap_files(File_Data const &f_data) */
    void sync_map(File_Data const & f_data)
    {
        using namespace std;
        synchronize_map( f_data.output_map );
#if 0
#if   defined( __gnu_linux__ )
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
    #error "threecrypt::sync_map currently only implemented for Gnu/Linux and 64-bit MS Windows"
#endif
#endif
    }/* ! sync_map(File_Data const &) */
    void set_file_size(OS_File_t const os_file, size_t const new_size)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( ftruncate( os_file, new_size ) == -1 )
        {
            perror ("Failed to set file size" );
            exit( EXIT_FAILURE );
#if 0
            fputs( "Error: Failed to set file size(int,size_t)\n", stderr );
            exit( EXIT_FAILURE );
#endif
        }
#elif defined( _WIN64 )
        LARGE_INTEGER large_int;
        large_int.QuadPart = static_cast<decltype(large_int.QuadPart)>(new_size);
        if ( SetFilePointerEx( os_file, large_int, NULL, FILE_BEGIN ) == 0 )
        {
            fputs( "Failed to SEtFilePointerEx()\n", stderr );
            exit( EXIT_FAILURE );
        }
        if ( SetEndOfFile( os_file ) == 0 )
        {
            fputs( "Failed to SetEndOfFile()\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "set_file_size only defined for Gnu/Linux and MS Windows"
#endif
    }/* ! set_file_size */
#if 0
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
#endif
    void set_file_size(char const * filename, size_t const new_size)
    {
        using namespace std;
#if defined( __gnu_linux__ )
        if ( truncate( filename, new_size ) == -1 )
        {
            perror( "Failed to set file size" );
            exit( EXIT_FAILURE );
        }
#else
        fputs( "ERROR: set_file_size(char const *filename, size_t const new_size) only defined for Gnu/Linux\n", stderr );
        exit( EXIT_FAILURE );
#endif
    }/* ! set_file_size */

} /* ! namespace threecrypt */
