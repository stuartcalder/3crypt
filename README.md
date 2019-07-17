# 3crypt

A simple command-line program for encrypting and decrypting files on Linux, built upon the Threefish block cipher
and the Skein hash function.
## Dependencies
-    [libssc](https://github.com/stuartcalder/ssc)
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
    3crypt --decrypt --input-filename $filename
```
## Building 3crypt
1. git clone [3crypt](https://github.com/stuartcalder/3crypt)
2. make
3. make install
