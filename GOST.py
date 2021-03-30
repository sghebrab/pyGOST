import random


def shift_11(msg_bin):
    return msg_bin[11:32] + msg_bin[0:11]


class GOST:
    BLOCK_LEN = 64
    KEY_LEN = 256
    _0xA, _0xB, _0xC, _0xD, _0xE, _0xF = 10, 11, 12, 13, 14, 15
    ECB, CBC = "ECB", "CBC"

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
        self.iv = None

    def get_message(self):
        return self.message

    def set_message(self, message):
        self.message = message
        if len(self.message) % 64 != 0:
            self.pad_message()

    def get_encrypted_msg(self):
        return self.encrypted

    def set_encrypted_msg(self, ciphertext):
        self.encrypted = ciphertext

    def get_key(self):
        return self.key

    def set_key(self, key):
        self.key = key
        self.derive_sub_keys()

    def get_sub_keys(self):
        return self.sub_keys

    def get_iv(self):
        return self.iv

    def set_iv(self, iv):
        self.iv = iv

    def init_iv(self):
        iv = []
        random.seed()
        for i in range(64):
            iv.append(str(random.randint(0, 1)))
        self.iv = ''.join(iv)

    def pad_message(self):
        message_len = len(self.message)
        len_after_pad = (message_len // 64 + 1) * 64
        self.message = self.message.ljust(len_after_pad, '0')

    def encrypt_block(self, message):
        if len(message) != self.BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = message[0:32]
        msg_lo = message[32:64]
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i % 8])
        for i in range(8, 0, -1):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i - 1])
        return msg_lo + msg_hi

    def decrypt_block(self, ciphertext):
        if len(ciphertext) != self.BLOCK_LEN:
            print("Error: block length must be 64 bits.")
            return
        msg_hi = ciphertext[0:32]
        msg_lo = ciphertext[32:64]
        for i in range(8):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i])
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[7 - (i % 8)])
        return msg_lo + msg_hi

    def f_round(self, msg_hi, msg_lo, sub_key):
        tmp = msg_lo
        modulo2add = bin((int(msg_lo, 2) + int(sub_key, 2)) % 2 ** 32)[2:].zfill(32)
        pass_s_box = self.s_box_half_block_in(modulo2add)
        shifted = shift_11(pass_s_box)
        msg_lo = bin(int(shifted, 2) ^ int(msg_hi, 2))[2:].zfill(32)
        msg_hi = tmp
        return msg_hi, msg_lo

    def s_box_half_block_in(self, half_block):
        result = ""
        for i in range(8):
            result = result + self.sub_box(half_block[i * 4:(i + 1) * 4], i)
        return result

    def sub_box(self, msg_bin, i):
        index = int(msg_bin, 2)
        return bin(self.SUB_BOXES[i][index])[2:].zfill(4)

    def encrypt(self, mode=CBC):
        messages = [self.message[i * self.BLOCK_LEN:(i + 1) * self.BLOCK_LEN] for i in
                    range(len(self.message) // self.BLOCK_LEN)]
        if mode == self.ECB:
            encrypted = []
            for i in range(len(messages)):
                encrypted.append(self.encrypt_block(messages[i]))
            self.encrypted = ''.join(encrypted)
            return self.encrypted
        elif mode == self.CBC:
            if self.iv is None:
                self.init_iv()
            curr_iv = self.iv
            encrypted = []
            for i in range(len(messages)):
                applied_mask = bin(int(messages[i], 2) ^ int(curr_iv, 2))[2:].zfill(self.BLOCK_LEN)
                curr_iv = self.encrypt_block(applied_mask)
                encrypted.append(curr_iv)
            self.encrypted = ''.join(encrypted)
            return self.encrypted
        else:
            print("Error: choose between ECB and CBC.")

    def decrypt(self, mode=CBC):
        messages = [self.encrypted[i * self.BLOCK_LEN:(i + 1) * self.BLOCK_LEN] for i in
                    range(len(self.encrypted) // self.BLOCK_LEN)]
        if mode == self.ECB:
            decrypted = []
            for i in range(len(messages)):
                decrypted.append(self.decrypt_block(messages[i]))
            self.decrypted = ''.join(decrypted)
            return self.decrypted
        elif mode == self.CBC:
            curr_iv = self.iv
            decrypted = []
            for i in range(len(messages)):
                dec = self.decrypt_block(messages[i])
                applied_mask = bin(int(dec, 2) ^ int(curr_iv, 2))[2:].zfill(self.BLOCK_LEN)
                curr_iv = messages[i]
                decrypted.append(applied_mask)
            self.decrypted = ''.join(decrypted)
            return self.decrypted
        else:
            print("Error: choose between ECB and CBC.")

    def derive_sub_keys(self):
        if len(self.key) != self.KEY_LEN:
            print("Error: key length must be 256 bits.")
            self.key = None
            return
        for i in range(8):
            self.sub_keys.append(self.key[32 * i:(i + 1) * 32])
