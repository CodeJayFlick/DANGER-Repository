class Apple8900Constants:
    MAGIC = "8900"
    MAGIC_BYTES = bytes(MAGIC.encode())
    MAGIC_LENGTH = len(MAGIC)

    FORMAT_ENCRYPTED = 3  # AES-128-CBC, 0x837 key and all zero IV
    FORMAT_PLAIN = 4

    AES_KEY_STRING = "188458A6D15034DFE386F23B61D43774"
    AES_KEY_BYTES = bytes(AES_KEY_STRING.encode())

    AES_IV_ZERO_BYTES = bytearray(16)
