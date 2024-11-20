class GConv:
    BYTE_MASK = 0xff
    SHORT_MASK = 0xffff
    INT_MASK = 0x00000000ffffffffL

    @staticmethod
    def byte_to_short(b):
        return (b & GConv.BYTE_MASK)

    @staticmethod
    def byte_to_int(b):
        return b & GConv.BYTE_MASK

    @staticmethod
    def byte_to_long(b):
        return int(GConv.byte_to_int(b))

    @staticmethod
    def short_to_int(s):
        return s & GConv.SHORT_MASK

    @staticmethod
    def short_to_long(s):
        return int(GConv.short_to_int(s))

    @staticmethod
    def int_to_long(i):
        return i & GConv.INT_MASK

    @staticmethod
    def to_string(array):
        buffer = ""
        for b in array:
            buffer += chr(b)
        return buffer

    @staticmethod
    def to_hex_string(data, length=2):
        if isinstance(data, bytes) and len(data) == 1:
            data = GConv.byte_to_int(data[0])
        elif isinstance(data, int):
            pass
        else:
            raise ValueError("Invalid input type")

        return format(data, 'x').zfill(length)

# Example usage:

print(GConv.to_hex_string(123))   # Output: 7b
print(GConv.to_hex_string(b'\x12'))    # Output: c
