# 3crypt
A simple C++17 command-line program for encrypting and decrypting files on OpenBSD, GNU/Linux, and Microsoft Windows(c), built upon the
Threefish block cipher and the Skein cryptographic hash function. 3crypt provides 512 bits of symmetric security.
## Buildtime Dependencies
### (OpenBSD, GNU/Linux, and Microsoft Windows(c))
-   [ssc](https://github.com/stuartcalder/ssc) header and library files.
-   __meson__ frontend build system.
-   __ninja__ backend build system.
### (GNU/Linux only)
-   __GCC 7+__ compiler.
-   __ncurses__ header and library files.
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
### On OpenBSD systems
1. build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the header files for [ssc](https://github.com/stuartcalder/ssc) are in __/usr/local/include/__.
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
5. 3crypt should now be successfully install on your OpenBSD system.
### On GNU/Linux systems
1. build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the header files for [ssc](https://github.com/stuartcalder/ssc) are in __/usr/include/__.
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
### On Microsoft Windows(c) systems
1. Before attempting to build 3crypt, build and install [ssc](https://github.com/stuartcalder/ssc).
	- Make sure the header files for [ssc](https://github.com/stuartcalder/ssc) are in __C:/include__.
	- Make sure that __ssc.lib__ is in __C:/lib__.
2. Create the directory __C:/bin__ if it does not exist.
3. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
4. cd into the 3crypt project directory, and execute:
```
meson --backend=ninja builddir
```
5. cd into builddir, and execute:
```
ninja
```
6. copy the output file, __3crypt.exe__ into the directory __C:/bin__.
