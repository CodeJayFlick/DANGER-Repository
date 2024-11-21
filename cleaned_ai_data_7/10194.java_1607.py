crc32tab = [0,1996959894,-301047508,...]  # You can copy-paste this list from your original code.

def hash_one_byte(hashcode, val):
    return crc32tab[(hashcode ^ val) & 0xff] ^ (hashcode >> 8)
