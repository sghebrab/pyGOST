from GOST import GOST
import my_utils
import base64

gost = GOST()
msg = "What if I try this?"
key = my_utils.gen_passwd_from_SHA256("My key")
gost.set_message(my_utils.string_to_bytes(msg))
gost.set_key(key)
gost.init_iv()
print("Msg: ", gost.get_message())
print("Key: ", gost.get_key())
print("IV: ", gost.get_iv())
ciphertext = gost.encrypt(gost.CBC)

print("Encrypted: ", base64.b64decode(ciphertext))

deciphered = gost.decrypt(gost.CBC)
print("Decrypted: ", my_utils.bytes_to_string(deciphered))

print(gost.get_message() == deciphered)

gost2 = GOST()
gost2.set_key(key)
gost2.set_iv(gost.get_iv())
gost2.set_encrypted_msg(ciphertext)
print(my_utils.bytes_to_string(gost2.decrypt()))