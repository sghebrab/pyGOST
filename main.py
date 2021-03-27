from GOST import GOST
import hashlib
import my_utils

gost = GOST()
msg = "Test sentence"
sha = hashlib.sha256()
sha.update(b"SecretKey")
bytes = sha.digest()
key = ""
for i in range(0, 32):
    key = key + bin(bytes[i])[2:].zfill(8)
gost.set_message(my_utils.string_to_bytes(msg))
gost.set_key(key)
gost.init_iv()
print("Msg: ", msg)
print("Key: ", gost.get_key())
print("IV: ", gost.get_iv())
ciphertext = gost.encrypt(gost.CBC)

print("Encrypted: ", ciphertext)

deciphered = gost.decrypt(gost.CBC)
print("Decrypted: ", my_utils.bytes_to_string(deciphered))

print(gost.get_message() == deciphered)