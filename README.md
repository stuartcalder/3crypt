# 3crypt
A simple C++17 command-line program for encrypting and decrypting files on Linux, built upon the Threefish block cipher
and the Skein hash function.
## Dependencies
-    __ncurses__
-    [ssc](https://github.com/stuartcalder/ssc)
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
## Building 3crypt
1. build and install [ssc](https://github.com/stuartcalder/ssc)
2. git clone [3crypt](https://github.com/stuartcalder/3crypt)
3. make 3crypt
4. make install
