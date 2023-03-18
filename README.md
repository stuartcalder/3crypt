# 3crypt
CLI file encryption program aiming for 512 bits of security.

![Alt text](/../screenshots/plaintext.png?raw=true "Before 3crypt Encryption")
![Alt text](/../screenshots/ciphertext.png?raw=true "After 3crypt Encryption")

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
## Buildtime Dependencies
### (Required on all supported systems)
-   [Base](https://github.com/stuartcalder/Base) header and library files.
-   [Skc](https://github.com/stuartcalder/Skc) header and library files.
-   __meson__ frontend build system.
-   __ninja__ backend build system.
### (Required on OpenBSD, FreeBSD, MacOS, and GNU/Linux)
-   __ncurses__ header and library files.
### (Required on Microsoft Windows only)
-   __Windows Vista/Server 2008__ or later.
-   __Visual Studio 2019__ development suite.
## How To Build 3crypt With Meson
### MacOS and BSD Build instructions
1. build and install [Base](https://github.com/stuartcalder/Base.git).
2. buidl and install [Skc](https://github.com/stuartcalder/Skc.git).
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
1. build and install [Base](https://github.com/stuartcalder/Base.git).
2. build and install [Skc](https://github.com/stuartcalder/Skc.git).
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
### Microsoft Windows build instructions
1. Build and install [Base](https://github.com/stuartcalder/Base.git).
2. Build and install [Skc](https://github.com/stuartcalder/Skc.git).
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
