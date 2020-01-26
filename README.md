# 3crypt
A simple C++17 command-line program for encrypting and decrypting files on OpenBSD, FreeBSD, GNU/Linux, and Microsoft Windows, built upon the
Threefish block cipher and the Skein cryptographic hash function. 3crypt provides 512 bits of symmetric security.

![Alt text](/../screenshots/plaintext.png?raw=true "Before 3crypt Encryption")
![Alt text](/../screenshots/ciphertext.png?raw=true "After 3crypt Encryption")

## Buildtime Dependencies
### (OpenBSD, FreeBSD, GNU/Linux, and Microsoft Windows)
-   [ssc](https://github.com/stuartcalder/ssc) header and library files.
-   __meson__ frontend build system.
-   __ninja__ backend build system.
-   __ncurses__ header and library files.
### (GNU/Linux only)
-   __GCC 7+__ compiler.
### (Microsoft Windows only)
-   __Windows Vista/Server 2008__ or later.
-   __Visual Studio 2019__ development suite.
## Encrypting files
```
3crypt -e -i $filename
```
or
```
3crypt --encrypt --input-file $filename
```
## Decrypting files
```
3crypt -d -i $filename
```
or
```
3crypt --decrypt --input-file $filename
```
## Building 3crypt with Meson
### On OpenBSD and FreeBSD systems
1. build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the root of the project directory for [ssc](https://github.com/stuartcalder/ssc) is in the __/usr/local/include__ directory.
2. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
3. cd into the 3crypt project directory, and execute:
```
meson --backend=ninja builddir
```
4. cd into builddir, and execute:
```
ninja
doas ninja install
```
5. 3crypt should now be successfully installed on your BSD system.
### On GNU/Linux systems
1. build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the root of the project directory for [ssc](https://github.com/stuartcalder/ssc) is in the __/usr/include__ directory.
2. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
3. cd into the 3crypt project directory, and execute:
```
meson --backend=ninja --prefix=/usr builddir
```
4. cd into builddir, and execute:
```
ninja
sudo ninja install
```
5. 3crypt should now be successfully installed on your GNU/Linux system.
### On Microsoft Windows systems
1. Before attempting to build 3crypt, build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the root of the project director for [ssc](https://github.com/stuartcalder/ssc) is in the __C:/include__ directory.
	  Create this directory if it does not exist.
	- Make sure that __ssc.lib__ is in the __C:/lib__ directory.
2. Create the directory __C:/bin__ if it does not exist.
3. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
4. Open a command-prompt, **specifically** you must open __"x64 Native Tools Command Prompt for VS 2019"__.
	* If you open a regular cmd.exe console, you will not be able to build 3crypt.
5. cd into the 3crypt project directory, and execute:
```
meson --backend=ninja builddir
```
6. cd into builddir, and execute:
```
ninja
```
7. copy the output file, __3crypt.exe__ into the directory __C:/bin__.
8. 3crypt should now be successfully installed on your 64-bit Windows system.
9. Now you can [add 3crypt to your PATH](https://stackoverflow.com/questions/9546324/adding-directory-to-path-environment-variable-in-windows) environment variable, or invoke 3crypt directly:
```
C:\bin\3crypt --encrypt --input-file plaintext --output-file ciphertext
```
