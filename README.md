# 3crypt
A simple C++17 command-line program for encrypting and decrypting files on Gnu/Linux and Microsoft Windows, built upon the Threefish block cipher
and the Skein cryptographic hash function.
## Universal Dependencies
-   [ssc](https://github.com/stuartcalder/ssc)
-   **Meson** (if using the Meson build system)
-   **Ninja** (if using the Meson build system)
### Linux-Specific Dependencies
-   **ncurses**
### Windows-Specific Dependencies
-   Requires Windows Vista / Server 2008 or later
## Encrypting files
```
    3crypt -e -i $filename
    or
    3crypt --encrypt --input-file $filename
```
## Decrypting files
```
    3crypt -d -i $filename
    or
    3crypt --decrypt --input-file $filename
```
## Building 3crypt on Linux ( Makefile method )
1. build and install [ssc](https://github.com/stuartcalder/ssc)
    - Make sure the header files for [ssc](https://github.com/stuartcalder/ssc)
      are in /usr/local/include
2. git clone [3crypt](https://github.com/stuartcalder/3crypt)
3. cd 3crypt
4. make 3crypt
5. make install
## Building 3crypt with Meson
### The Linux Method
1. build and install [ssc](https://github.com/stuartcalder/ssc) using any
   supported method into /usr/lib64
    - Make sure the header files for [ssc](https://github.com/stuartcalder/ssc)
      are in /usr/local/include/
2. git clone [3crypt](https://github.com/stuartcalder/3crypt)
3. cd 3crypt
4. meson --prefix=/usr builddir
5. cd builddir
6. ninja
7. ninja install (**as root**)
### The Windows Method
1. build and install [ssc](https://github.com/stuartcalder/ssc) using Meson.
    - Make sure the header files for [ssc](https://github.com/stuartcalder/ssc)
      are in C:/local/include
2. git clone [3crypt](https://github.com/stuartcalder/3crypt)
3. cd 3crypt
4. meson --backend ninja builddir
5. cd builddir
6. ninja
7. rename the output file, **libssc.a**, to **ssc.lib**
8. copy **ssc.lib** to **C:/local/include**
