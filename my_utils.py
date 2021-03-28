import hashlib


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
        else:
            char = int(byte_list[i][5:8] + byte_list[i+1][2:8] + byte_list[i+2][2:8] + byte_list[i+3][2:8], 2)
            result += chr(char)
            i += 3
        i += 1
    return result


def gen_passwd_from_SHA256(password):
    sha = hashlib.sha256()
    sha.update(bytes(password, 'utf-8'))
    sha_to_bytes = sha.digest()
    key = ""
    for i in range(0, 32):
        key = key + bin(sha_to_bytes[i])[2:].zfill(8)
    return key


def encode_base64(message):
    map = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
           "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
           "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
           "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]
    encoded = []
    for i in range(len(message) // 6):
        char = message[i*6:(i+1)*6]
        char_to_num = int(char, 2)
        encoded.append(map[char_to_num])
    return ''.join(encoded)


def decode_base64(message):
    map = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
           "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
           "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
           "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]
    decoded = []
    for i in range(len(message)):
        char = map.index(message[i])
        char_to_num = bin(char)[2:].zfill(6)
        decoded.append(char_to_num)
    return ''.join(decoded)


def leading_zeros_hex(bin_message):
    length = len(bin_message)
    final_length = 0
    if length % 64 != 0:
        final_length = (length // 64 + 1)*64
    final_message = hex(int(bin_message))[2:].zfill(final_length)
    return final_message
