import hashlib
import random
import string
from datetime import datetime


def string_to_bytes(message):
    bin_array = bytearray(message, "utf8")
    byte_list = list()
    for b in bin_array:
        to_bin = bin(b)[2:].zfill(8)
        byte_list.append(to_bin)
    return ''.join(byte_list)


def bytes_to_string(bytes_in):
    result = ""
    byte_list = list()
    for i in range(0, len(bytes_in), 8):
        bin_int = bytes_in[i:i+8]
        byte_list.append(bin_int)
    i = 0
    while i < len(byte_list):
        if byte_list[i][0] == "0":
            char = int(byte_list[i], 2)
            result += chr(char)
        elif byte_list[i][0:3] == "110" and byte_list[i+1][0:2] == "10":
            char = int(byte_list[i][3:8] + byte_list[i+1][2:8], 2)
            result += chr(char)
            i += 1
        elif byte_list[i][0:4] == "1110" and byte_list[i+1][0:2] == "10" and byte_list[i+2][0:2] == "10":
            char = int(byte_list[i][4:8] + byte_list[i+1][2:8] + byte_list[i+2][2:8], 2)
            result += chr(char)
            i += 2
        elif byte_list[i][0:5] == "11110" and byte_list[i+1][0:2] == "10" and byte_list[i+2][0:2] == "10" and byte_list[i+3][0:2] == "10":
            char = int(byte_list[i][5:8] + byte_list[i+1][2:8] + byte_list[i+2][2:8] + byte_list[i+3][2:8], 2)
            result += chr(char)
            i += 3
        else:
            print("Error: a character cannot be decoded.")
            return
        i += 1
    return result


def pbkdf2(password, salt=None):
    if salt is None:
        salt = random_salt()
    key_bytes = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(salt, 'utf-8'), 10000)
    # sha = hashlib.sha256()
    # sha.update(bytes(password, 'utf-8'))
    # sha_to_bytes = sha.digest()
    key = ""
    for i in range(0, 32):
        key = key + bin(key_bytes[i])[2:].zfill(8)
    return key, salt


# def encode_base64(message):
#     map = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
#            "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
#            "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
#            "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]
#     encoded = []
#     for i in range(len(message) // 6):
#         char = message[i*6:(i+1)*6]
#         char_to_num = int(char, 2)
#         encoded.append(map[char_to_num])
#     return ''.join(encoded)
#
#
# def decode_base64(message):
#     b64_map = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
#            "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
#            "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
#            "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]
#     decoded = []
#     for i in range(len(message)):
#         char = b64_map.index(message[i])
#         char_to_num = bin(char)[2:].zfill(6)
#         decoded.append(char_to_num)
#     return ''.join(decoded)


def leading_zeros_hex(bin_message):
    length = len(bin_message)
    if length % 64 != 0:
        final_length = (length // 64 + 1)*64
        return hex(int(bin_message, 2))[2:].zfill(final_length)
    return hex(int(bin_message, 2))[2:]


def random_salt(size=20):
    result = ""
    random.seed()
    for i in range(size):
        rnd = random.randint(0, 3)
        if rnd == 0:
            result += random.choice(string.ascii_uppercase)
        elif rnd == 1:
            result += random.choice(string.ascii_lowercase)
        elif rnd == 2:
            result += random.choice(string.digits)
        else:
            result += random.choice(string.punctuation)
    return result


# This function takes as input a hex string and returns a binary strings whose length is
# the minimum multiple of 64 above the length of the binarized hex string.
# e.g. if hex string translates to 1101, then the result will be 62 zeros plus 1101
def hex_to_bin_mult_64(hex_message):
    length = len(bin(int(hex_message, 16))[2:])
    if length % 64 != 0:
        final_length = (length // 64 + 1) * 64
        return bin(int(hex_message, 16))[2:].zfill(final_length)
    return bin(int(hex_message, 16))[2:]


def write_to_file(path, ciphertext, iv, salt=None):
    print("Writing to " + path + "...")
    today = datetime.today().strftime("%d/%m/%Y")
    file_handle = open(path, "a")
    file_handle.write("Date: " + str(today) + "\n")
    file_handle.write("Ciphertext (hex): " + ciphertext + "\n")
    if salt is not None:
        file_handle.write("Salt: " + salt + "\n")
    file_handle.write("IV (hex): " + iv + "\n\n")
    print("Done writing!")


def odds_zeros_ones(bin_message):
    zeros = 0
    ones = 0
    for b in bin_message:
        if b == "0":
            zeros += 1
        else:
            ones += 1
    return 100*zeros/len(bin_message), 100*ones/len(bin_message)
