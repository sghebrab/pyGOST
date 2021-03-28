from GOST import GOST
import my_utils
import time

gost = GOST()
msg = "I love GOST cryptosystem!"
key = my_utils.gen_passwd_from_SHA256("GOST is the best algorithm")
t1 = time.time()
gost.set_message(my_utils.string_to_bytes(msg))
gost.set_key(key)
gost.init_iv()
print("Msg: ", msg)
print("Key: ", my_utils.leading_zeros_hex(key))
print("IV: ", my_utils.leading_zeros_hex(gost.get_iv()))
ciphertext = my_utils.leading_zeros_hex(gost.encrypt(gost.CBC))

print("Encrypted: ", ciphertext)

deciphered = gost.decrypt(gost.CBC)
print("Decrypted: ", my_utils.bytes_to_string(deciphered))
t2 = time.time()
print("Elapsed time (s): ", t2 - t1)

#print(gost.get_message() == deciphered)

gost2 = GOST()
gost2.set_key(key)
gost2.set_iv(gost.get_iv())
gost2.set_encrypted_msg(bin(int(ciphertext, 16))[2:].zfill(256))

print(bin(int(ciphertext, 16))[2:].zfill(256))
print(my_utils.bytes_to_string(gost2.decrypt()))
