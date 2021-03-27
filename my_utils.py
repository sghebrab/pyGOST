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