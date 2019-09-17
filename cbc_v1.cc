/*
Copyright 2019 Stuart Steven Calder

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "cbc_v1.hh"

namespace threecrypt::cbc_v1 {

	static size_t
	calculate_CBC_V1_size (size_t pre_encryption_size) {
		constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
		auto s = pre_encryption_size;
		if ( s < Block_Bytes )
			s = Block_Bytes;
		else
			s += ( Block_Bytes - (s % Block_Bytes) );
		return s + File_Metadata_Size;
	}

	void
	CBC_V1_encrypt (char const * __restrict input_filename, char const * __restrict output_filename) {
		using namespace std;
		ssc::OS_Map input_map, output_map;
		input_map.os_file = ssc::open_existing_os_file( input_filename, true );
		output_map.os_file = ssc::create_os_file( output_filename );

		input_map.size = ssc::get_file_size( input_map.os_file );
		output_map.size = calculate_CBC_V1_size( input_map.size );
		ssc::set_os_file_size( output_map.os_file, output_map.size );

		ssc::map_file( input_map, true );
		ssc::map_file( output_map, false );
		char password [Max_Password_Length + 1];
		int password_length;
		{
			ssc::Terminal term;
			char pwcheck [Max_Password_Length + 1];
			bool repeat = true;
			do {
				static_assert (sizeof(password) == sizeof(pwcheck));
				memset( password, 0, sizeof(password) );
				memset( pwcheck , 0, sizeof(pwcheck)  );
				password_length = term.get_pw( password, Max_Password_Length, 1 );
				static_cast<void>(term.get_pw( pwcheck , Max_Password_Length, 1 ));
				if ( memcmp( password, pwcheck, sizeof(password) ) == 0 )
					repeat = false;
				else
					term.notify( "Passwords do not match.\n" );
			} while (repeat);
			ssc::zero_sensitive( pwcheck, sizeof(pwcheck) );
		}
		CBC_V1_Header_t header;
		memcpy( header.id, CBC_V1_ID, sizeof(header.id) );
		header.total_size = static_cast<decltype(header.total_size)>(output_map.size);
		ssc::generate_random_bytes( header.tweak      , sizeof(header.tweak)       );
		ssc::generate_random_bytes( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
		ssc::generate_random_bytes( header.cbc_iv     , sizeof(header.cbc_iv)      );
		header.num_iter   = 1'000'000;
		header.num_concat = 1'000'000;
		u8_t * out = output_map.ptr;
		memcpy( out, &header, sizeof(header) );
		out += sizeof(header);
		u8_t derived_key [Block_Bytes];
		ssc::sspkdf( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		ssc::zero_sensitive( password, sizeof(password) );
		{
			CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
			out += cbc.encrypt( input_map.ptr, out, input_map.size, header.cbc_iv );
		}
		{
			Skein_t skein;
			skein.message_auth_code( out, output_map.ptr, derived_key, output_map.size - MAC_Bytes, sizeof(derived_key), MAC_Bytes );
		}
		ssc::zero_sensitive( derived_key, sizeof(derived_key) );
		ssc::sync_map( output_map );
		ssc::unmap_file( input_map );
		ssc::unmap_file( output_map );
		ssc::close_os_file( input_map.os_file );
		ssc::close_os_file( output_map.os_file );
	}/* CBC_V1_encrypt */
	
	void
	CBC_V1_decrypt	(char const * __restrict input_filename, char const * __restrict output_filename) {
		using namespace std;
		ssc::OS_Map input_map, output_map;

		input_map.os_file = ssc::open_existing_os_file( input_filename, true );
		output_map.os_file = ssc::create_os_file( output_filename );
		input_map.size = ssc::get_file_size( input_map.os_file );
		output_map.size = input_map.size;

		/* The smallest a CBC_V1 encrypted file could ever be is one
		* CBC_V1-Header, one CBC-encrypted block, and one 512-bit
		* Message-Authentication-Code */
		static constexpr auto const Minimum_Possible_File_Size = sizeof(CBC_V1_Header_t) + Block_Bytes + MAC_Bytes;
		if (input_map.size < Minimum_Possible_File_Size) {
			fputs( "Error: Input file doesn't appear to be large enough to be a CBC_V1 encrypted file\n", stderr );
			ssc::close_os_file( input_map.os_file );
			ssc::close_os_file( output_map.os_file );
			remove( output_filename );
			exit( EXIT_FAILURE );
		}
		ssc::set_os_file_size( output_map.os_file, output_map.size );
		ssc::map_file( input_map, true );
		ssc::map_file( output_map, false );
		u8_t const * in = input_map.ptr;
		CBC_V1_Header_t header;                 // Declare a CBC_V1 header, to store the header from the input file                 
		memcpy( &header, in, sizeof(header) );  // Copy the header from the input file into 
		in += sizeof(header);                   // Increment the pointer by the size of the copied header
		static_assert (sizeof(header.id) == ssc::static_strlen(CBC_V1_ID));	// Ensure we know the sizes
		if (memcmp( header.id, CBC_V1_ID, sizeof(header.id) ) != 0) {		// If the copied-in header isn't a CBC_V1 header ...
			// Cleanup & Die
			fprintf( stderr, "Error: The input file doesn't appear to be a `%s` encrypted file.\n", CBC_V1_ID );
			ssc::unmap_file( input_map );
			ssc::unmap_file( output_map );
			ssc::close_os_file( input_map.os_file );
			ssc::close_os_file( output_map.os_file );
			remove( output_filename );
			exit( EXIT_FAILURE );
		}
		if (header.total_size != static_cast<decltype(header.total_size)>(input_map.size)) {
			fprintf( stderr, "Error: Input file size (%zu) does not equal the fiel size in the file header (%zu)\n",
			header.total_size, input_map.size );
			ssc::unmap_file( input_map );
			ssc::unmap_file( output_map );
			ssc::close_os_file( input_map.os_file );
			ssc::close_os_file( output_map.os_file );
			remove( output_filename );
			exit( EXIT_FAILURE );
		}
		char password [Max_Password_Length] = { 0 }; // Declare a buffer, big enough for Max-Password_Length characters and a null
		int password_length;                         // Prepare to store the length of the password
		{
			ssc::Terminal term;	// Create a ssc::Terminal abstraction
			password_length = term.get_pw( password, Max_Password_Length, 1 );// Copy terminally-input password into the password buffer
		}
		u8_t derived_key [Block_Bytes];         // Declare a buffer, big enough to store a 512-bit symmetric key
		/* Hash the password, with the random salt and compile-time iteration
		and concatenation constants */
		ssc::sspkdf( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		ssc::zero_sensitive( password, sizeof(password) ); // Securely zero over the entire password buffer
		{
			Skein_t skein;              // Declare a skein cryptographic Hash-Function object
			u8_t gen_mac [MAC_Bytes];   // Declare a 512-bit buffer, for storing the Message Authentication Code
			skein.message_auth_code( gen_mac, input_map.ptr, derived_key,
						 input_map.size - MAC_Bytes, sizeof(derived_key), sizeof(gen_mac) );
			if (memcmp( gen_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes ) != 0) {
				fputs( "Error: Authentication failed.\n"
				       "Possibilities: wrong password, the file is corrupted, or it has been somehow tampered with.\n", stderr );
				ssc::zero_sensitive( derived_key, sizeof(derived_key) );
				ssc::unmap_file( input_map );
				ssc::unmap_file( output_map );
				ssc::close_os_file( input_map.os_file );
				ssc::close_os_file( output_map.os_file );
				remove( output_filename );
				exit( EXIT_FAILURE );
			}
		}
		size_t plaintext_size; // Prepare to store the size of the plaintext, in bytes
		{
			/* Create a CipherBlockChaining object using Threefish and the
			* derived key & cipher tweak. Prepare to decrypt.
			*/
			CBC_t cbc{ Threefish_t{ derived_key, header.tweak } };
			ssc::zero_sensitive( derived_key, sizeof(derived_key) ); // Securely zero over the derived key, now that we'v consumed it.
			/* All the metadata of a CBC_V1 encrypted file is in the header,
			* and the M.A.C. appended to the end of the file
			*/
			static constexpr auto const File_Metadata_Size = sizeof(CBC_V1_Header_t) + MAC_Bytes;
			// Record the number of plaintext bytes during the decrypt
			plaintext_size = cbc.decrypt( in, output_map.ptr, input_map.size - File_Metadata_Size, header.cbc_iv );
		}
		ssc::sync_map( output_map );
		ssc::unmap_file( input_map );
		ssc::unmap_file( output_map );
		ssc::set_os_file_size( output_map.os_file, plaintext_size );
		ssc::close_os_file( input_map.os_file );
		ssc::close_os_file( output_map.os_file );
	}
} /* ! namespace threecrypt::cbc_v1 */
