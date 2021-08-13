# GOST-cipher
This Python program provides an implementation of the soviet GOST cipher.
The GOST cipher is a symmetric block cipher that works on 64 bit blocks using 256 bit keys.
The S-Boxes used in this implementation are conformed to the standard GOST R 34.12-2015.

To use the cipher, you need to import the library GOST and instantiate a GOST object.
Use the setter methods to set the plaintext (or ciphertext), the key and, in case you want to use the cipher in CBC mode, you have to possibility to set the IV.
The parameters required are always in binary form, so strings containing only 0s and 1s. Beware that these parameters are strings, not binary numbers!!
Using the encrypt and the decrypt methods (specifying, optionally, ECB or CBC mode) you'll be able to encrypt and decrypt the message you set or the ciphertext.
If you encrypt a message, the result will also be stored in a GOST attribute, namely self.encrypted; if you then use the decrypt method, you won't need to set the ciphertext because it's already there.

As of now, the library supports ECB, CBC, OFB and CFB modes.

Here is an example of how the program should be used for both encryption an decryption.

# Encryption

from GOST import GOST

import my_utils

gost = GOST()

key, salt = my_utils.pbkdf2('Password', 'Salt')

gost.set_message(my_utils.string_to_bytes('Hello, world!'))

gost.set_key(key)

gost.set_operation_mode(gost.CBC)

gost.encrypt()

// you can get the resulting ciphertext with gost.get_encrypted_msg() and the IV with gost.get_iv()

// the IV is randomly generated if not provided in the setup phase

# Decryption

from GOST import GOST

import my_utils

gost = GOST()

key, salt = my_utils.pbkdf2('Password', 'Salt')

ciphertext = // a k&ast;64 character string, where k = 0, 1, ...

iv = // a 256 character string containing only 0s and 1s

gost.set_iv(iv)

gost.set_key(key)

gost.set_operation_mode(gost.CBC)

gost.set_encrypted_msg(ciphertext)

gost.decrypt()

# NOTES
Beware that when the programs produces outputs, there could be some mismatches in the length of the strings.
Suppose that the ciphertext is 63 zeros and a single 1. Then the result would be 1 because the 0s are trimmed out.
If you use the functions in my_utils (namely, hex_to_bin_mult_64 and leading_zeros_hex) you'll be able to overcome this problem.
