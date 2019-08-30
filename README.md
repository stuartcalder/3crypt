# 3crypt
A simple C++17 command-line program for encrypting and decrypting files on Gnu/Linux and Microsoft Windows, built upon the Threefish block cipher
and the Skein cryptographic hash function.
## Buildtime Dependencies
### (Gnu/Linux and Microsoft Windows)
-   [ssc](https://github.com/stuartcalder/ssc) header and library files.
-   __meson__ frontend build system.
-   __ninja__ backend build system.
### (Gnu/Linux only)
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
### The Gnu/Linux Method
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
5. 3crypt should now be successfully installed on your Gnu/Linux system.
### The Microsoft Windows Method
1. build and install [ssc](https://github.com/stuartcalder/ssc).
    - Make sure the header files for [ssc](https://github.com/stuartcalder/ssc) are in __C:/include/__.
2. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
3. cd into the 3crypt project directory, and execute:
```
meson --backend=ninja builddir
```
4. cd into builddir, and execute:
```
ninja
```
5. copy the output file, __3crypt.exe__ into the directory __C:/bin/__.
