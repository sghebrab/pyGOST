# GOST-cipher
This Python program provides an implementation of the soviet GOST cipher.
The GOST cipher is a symmetric block cipher that works on 64 bit blocks using 256 bit keys.
The S-Boxes used in this implementation are conformed to the standard GOST R 34.12-2015.

To use the cipher, you need to import the library GOST and instantiate a GOST object.
Use the setter methods to set the plaintext (or ciphertext), the key and, in case you want to use the cipher in CBC mode, you have to possibility to set the IV.
The parameters required are always in binary form, so strings containing only 0s and 1s.
Using the encrypt and the decrypt methods (specifying, optionally, ECB or CBC mode) you'll be able to encrypt and decrypt the message you set or the ciphertext.
If you encrypt a message, the result will also be stored in a GOST attribute, namely self.encrypted; if you then use the decrypt method, you won't need to set the ciphertext because it's already there.
