import hashlib

class GOST:
    BLOCK_LEN = 64
    KEY_LEN = 256
    _0xA, _0xB, _0xC, _0xD, _0xE, _0xF = 10, 11, 12, 13, 14, 15

    SUB_BOXES = [
        [_0xC, 4, 6, 2, _0xA, 5, _0xB, 9, _0xE, 8, _0xD, 7, 0, 3, _0xF, 1],
        [6, 8, 2, 3, 9, _0xA, 5, _0xC, 1, _0xE, 4, 7, _0xB, _0xD, 0, _0xF],
        [_0xB, 3, 5, 8, 2, _0xF, _0xA, _0xD, _0xE, 1, 7, 4, _0xC, 9, 6, 0],
        [_0xC, 8, 2, 1, _0xD, 4, _0xF, 6, 7, 0, _0xA, 5, 3, _0xE, 9, _0xB],
        [7, _0xF, 5, _0xA, 8, 1, 6, _0xD, 0, 9, 3, _0xE, _0xB, 4, 2, _0xC],
        [5, _0xD, _0xF, 6, 9, 2, _0xC, _0xA, _0xB, 7, 8, 1, 4, 3, _0xE, 0],
        [8, _0xE, 2, 5, 6, 9, 1, _0xC, _0xF, 4, _0xB, 0, _0xD, _0xA, 3, 7],
        [1, 7, _0xE, _0xD, 0, 5, 8, 3, 4, _0xF, _0xA, 6, 9, _0xC, _0xB, 2],
    ]


    def __init__(self):
        self.message = None
        self.key = None
        self.sub_keys = None

    def set_message(self, message):
        self.message = bin(message)

    def set_key(self, key):
        self.key = key
        self.sub_keys = self.derive_subkeys(key)

    def encipher_block(self, bin_msg, subkeys):
        if len(bin_msg) != self.BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = bin_msg[0:32]
        msg_lo = bin_msg[32:64]
        for i in range(24):
            msg_hi, msg_lo = f_round(msg_hi, msg_lo, subkeys[i % 8])
            #print("Enc round: ", i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i % 8)
        for i in range(8, 0, -1):
            msg_hi, msg_lo = f_round(msg_hi, msg_lo, subkeys[i - 1])
            #print("Enc round: ", 32-i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i - 1)
        return msg_lo + msg_hi

    def decipher_block(bin_msg, subkeys, iv=None):
        if len(bin_msg) != BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = bin_msg[0:32]
        msg_lo = bin_msg[32:64]
        for i in range(8):
            msg_hi, msg_lo = f_round(msg_hi, msg_lo, subkeys[i])
            #print("Dec round: ", i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i)
        for i in range(24):
            msg_hi, msg_lo = f_round(msg_hi, msg_lo, subkeys[7 - (i % 8)])
            #print("Dec round: ", i+8, "Block: ", msg_hi + msg_lo, "Subkey #: ", 7 - i % 8)
        return msg_lo + msg_hi


    def f_round(msg_hi, msg_lo, sub_key):
        tmp = msg_lo
        modulo2add = bin((int(msg_lo, 2) + int(sub_key, 2)) % 2**32)[2:].zfill(32)
        pass_sbox = s_box_hblock_in(modulo2add)
        shifted = shift_11(pass_sbox)
        msg_lo = bin(int(shifted, 2) ^ int(msg_hi, 2))[2:].zfill(32)
        msg_hi = tmp
        return msg_hi, msg_lo


    def s_box_hblock_in(half_block):
        result = ""
        for i in range(8):
            result = result + sub_box(half_block[i*4:(i+1)*4], i)
        return result


    def sub_box(msg_bin, i):
        index = int(msg_bin, 2)
        return bin(SUB_BOXES[i][index])[2:].zfill(4)


    def shift_11(msg_bin):
        return msg_bin[11:32] + msg_bin[0:11]


    def derive_subkeys(key):
        if len(key) != KEY_LEN:
            print("Error: key length must be 256 bits.")
            return
        sub_keys = []
        for i in range(8):
            sub_keys.append(key[8 * i:(i + 1) * 8])
        return sub_keys

gost = GOST()
msg = bin(157)[2:].zfill(64)
sha = hashlib.sha256()
sha.update(b"SecretKey")
bytes = sha.digest()
key = ""
for i in range(0, 32):
    key = key + bin(bytes[i])[2:].zfill(8)
sub_keys = derive_subkeys(key)
#iv = bin(0)[2:].zfill(64)
print("Msg: ", msg, '\n', "Key: ", key, '\n', "IV: ")
ciphertext = encipher_block(msg, sub_keys)
print(ciphertext)

deciphered = decipher_block(ciphertext, sub_keys)
print(deciphered)