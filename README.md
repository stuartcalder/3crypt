# 3crypt
CLI file encryption program aiming for 512 bits of security.

![Alt text](/../screenshots/plaintext.png?raw=true "Before 3crypt Encryption")
![Alt text](/../screenshots/ciphertext.png?raw=true "After 3crypt Encryption")

## Buildtime Dependencies
### (Required on all supported systems)
-   [shim](https://github.com/stuartcalder/shim) header and library files.
-   [symm](https://github.com/stuartcalder/symm) header and library files.
-   __meson__ frontend build system.
-   __ninja__ backend build system.
### (Required on OpenBSD, FreeBSD, Mac OSX, and GNU/Linux)
-   __ncurses__ header and library files.
### (Required on Microsoft Windows only)
-   __Windows Vista/Server 2008__ or later.
-   __Visual Studio 2019__ development suite.
## How To Encrypt Files
```
3crypt -e -i $filename
```
or
```
3crypt --encrypt --input $filename
```
## How To Decrypt Files
```
3crypt -d -i $filename
```
or
```
3crypt --decrypt --input $filename
```
## How To Build 3crypt With Meson
### Mac OSX and BSD Build instructions
1. build and install [shim](https://github.com/stuartcalder/shim.git).
2. buidl and install [symm](https://github.com/stuartcalder/symm.git).
3. git clone [3crypt](https://github.com/stuartcalder/3crypt.git) anywhere.
4. cd into the 3crypt project directory and execute the following:
```
$ meson --backend=ninja builddir
```
5. cd into builddir, and execute the following:
```
$ ninja
# ninja install
```
### GNU/Linux build instructions
1. build and install [shim](https://github.com/stuartcalder/shim.git).
2. build and install [symm](https://github.com/stuartcalder/symm.git).
3. git clone [3crypt](https://github.com/stuartcalder/3crypt) anywhere.
4. cd into the 3crypt project directory and execute the following:
```
$ meson --backend=ninja --prefix=/usr builddir
```
5. cd into builddir and execute the following:
```
$ ninja
# ninja install
```
### On Microsoft Windows systems
1. Build and install [shim](https://github.com/stuartcalder/shim.git).
2. Build and install [symm](https://github.com/stuartcalder/symm.git).
3. git clone [3crypt](https://github.com/stuartcalder/3crypt.git) anywhere.
4. Open a command-prompt, **specifically** you must open __"x64 Native Tools Command Prompt for VS 2019"__.
```
meson --backend=ninja builddir
```
5. cd into builddir, and execute the following:
```
ninja
```
6. Optionally, you may now [add 3crypt to your PATH environment variable](https://stackoverflow.com/questions/9546324/adding-directory-to-path-environment-variable-in-windows), or invoke it directly by executing the following from a cmd window:
```
C:\bin\3crypt --encrypt --input plaintext_file --output ciphertext_file
```
