import hashlib
import random
import string
from datetime import datetime


# This function takes as input a string and returns another string where each original character has been replaced by
# its UTF-8 encoding (e.g. "a" -> "01100001".
def string_to_bytes(message):
    bin_array = bytearray(message, "utf8")
    byte_list = list()
    for b in bin_array:
        # Since if b has leading zeros they are discarded when converting to bin, zfill(8) pads the bin number with as
        # many 0s as needed to make it 8 characters long
        to_bin = bin(b)[2:].zfill(8)
        byte_list.append(to_bin)
    return ''.join(byte_list)


# This function takes as input a string of bytes, i.e. a string containing only 0s and 1s, whose lenght is a multiple
# of 8. It tries to perform UTF-8 encoding on each byte (or sequence of bytes for non-ASCII characters).
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


def pbkdf2(password, salt=None, iter=300000):
    # If salt is None, generate a random salt
    if salt is None:
        salt = random_salt()
    # Derive the key by hashing the password along with salt
    key_bytes = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(salt, 'utf-8'), iter)
    key = ""
    # Since key_bytes is a list of bytes with length 32 (32*8 = 256 -> sha256), take every byte, convert it to bin, fill
    # it with leading zeros and append the result to the whole key
    for i in range(0, 32):
        key = key + bin(key_bytes[i])[2:].zfill(8)
    return key, salt


def leading_zeros_hex(bin_message):
    hex_chars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
    length = len(bin_message)
    if length % 64 != 0:
        final_length = (length // 64 + 1)*64
        # Compute how many 0s are needed to make the message's length a multiple of 64
        missing_zeros = final_length - length
        # Append those 0s at the beginning of the string
        bin_message = "0"*missing_zeros + bin_message
    hex_msg = []
    for i in range(0, len(bin_message), 4):
        # Take 4 bits at a time, convert that value to int and index the hex_chars list to obtain the right character
        idx = int(bin_message[i:i+4], 2)
        hex_msg.append(hex_chars[idx])
    return "".join(hex_msg)


def random_salt(size=20):
    result = ""
    random.seed()
    for i in range(size):
        # Take a random character between uppercase letters, lowercase letters, digits and punctuation characters
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


# This function takes as input a hex string and returns a binary string whose length is
# the minimum multiple of 64 above the length of the binarized hex string.
# e.g. if hex string translates to 1101, then the result will be 60 zeros plus 1101
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


# This is just to see how good the algorithm is at performing confusion.
def odds_zeros_ones(bin_message):
    zeros = 0
    ones = 0
    for b in bin_message:
        if b == "0":
            zeros += 1
        else:
            ones += 1
    return 100*zeros/len(bin_message), 100*ones/len(bin_message)
