import hashlib


def shift_11(msg_bin):
    return msg_bin[11:32] + msg_bin[0:11]


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
        self.sub_keys = []
        self.encrypted = None
        self.decrypted = None

    def get_message(self):
        return self.message

    def set_message(self, message):
        self.message = bin(message)[2:]
        if len(self.message) % 64 != 0:
            self.pad_message()

    def set_encrypted_msg(self, ciphertext):
        self.encrypted = ciphertext

    def get_key(self):
        return self.key

    def set_key(self, key):
        self.key = key
        self.derive_subkeys()

    def get_sub_keys(self):
        return self.sub_keys

    def pad_message(self):
        message_len = len(self.message)
        len_after_pad = (message_len // 64 + 1)*64
        self.message = self.message.zfill(len_after_pad)

    def encipher_block(self):
        if len(self.message) != self.BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = self.message[0:32]
        msg_lo = self.message[32:64]
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i % 8])
            #print("Enc round: ", i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i % 8)
        for i in range(8, 0, -1):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i - 1])
            #print("Enc round: ", 32-i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i - 1)
        self.encrypted = msg_lo + msg_hi
        return self.encrypted

    def decipher_block(self):
        if len(self.message) != self.BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = self.encrypted[0:32]
        msg_lo = self.encrypted[32:64]
        for i in range(8):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i])
            #print("Dec round: ", i, "Block: ", msg_hi + msg_lo, "Subkey #: ", i)
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[7 - (i % 8)])
            #print("Dec round: ", i+8, "Block: ", msg_hi + msg_lo, "Subkey #: ", 7 - i % 8)
        self.decrypted = msg_lo + msg_hi
        return self.decrypted

    def f_round(self, msg_hi, msg_lo, sub_key):
        tmp = msg_lo
        modulo2add = bin((int(msg_lo, 2) + int(sub_key, 2)) % 2**32)[2:].zfill(32)
        pass_sbox = self.s_box_hblock_in(modulo2add)
        shifted = shift_11(pass_sbox)
        msg_lo = bin(int(shifted, 2) ^ int(msg_hi, 2))[2:].zfill(32)
        msg_hi = tmp
        return msg_hi, msg_lo

    def s_box_hblock_in(self, half_block):
        result = ""
        for i in range(8):
            result = result + self.sub_box(half_block[i*4:(i+1)*4], i)
        return result

    def sub_box(self, msg_bin, i):
        index = int(msg_bin, 2)
        return bin(self.SUB_BOXES[i][index])[2:].zfill(4)

    def derive_subkeys(self):
        if len(self.key) != self.KEY_LEN:
            print("Error: key length must be 256 bits.")
            self.key = None
            return
        for i in range(8):
            self.sub_keys.append(key[32 * i:(i + 1) * 32])


gost = GOST()
msg = 157
sha = hashlib.sha256()
sha.update(b"SecretKey")
bytes = sha.digest()
key = ""
for i in range(0, 32):
    key = key + bin(bytes[i])[2:].zfill(8)
gost.set_message(msg)
gost.set_key(key)
print("Msg: ", msg)
print("Key: ", int(gost.get_key(), 2))
ciphertext = gost.encipher_block()
print("Encrypted: ", int(ciphertext, 2))

deciphered = gost.decipher_block()
print("Decrypted: ", int(deciphered, 2))