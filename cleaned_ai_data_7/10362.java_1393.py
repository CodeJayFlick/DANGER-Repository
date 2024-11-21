class Conv:
    BYTE_MASK = 0xff
    SHORT_MASK = 0xffff
    INT_MASK = 0x00000000ffffffffL

    @staticmethod
    def byte_to_short(b):
        return (b & Conv.BYTE_MASK)

    @staticmethod
    def byte_to_int(b):
        return b & Conv.BYTE_MASK

    @staticmethod
    def byte_to_long(b):
        return int(Conv.byte_to_int(b))

    @staticmethod
    def short_to_int(s):
        return s & Conv.SHORT_MASK

    @staticmethod
    def short_to_long(s):
        return int(Conv.short_to_int(s))

    @staticmethod
    def int_to_long(i):
        return i & Conv.INT_MASK

    @staticmethod
    def to_string(array):
        buffer = ""
        for b in array:
            buffer += chr(b)
        return buffer

    @staticmethod
    def to_hex_string(val, length=2):
        if isinstance(val, bytes):
            val = int.from_bytes(val, 'big')
        elif not isinstance(val, int):
            raise TypeError("Invalid type")
        hex_str = format(val, 'x').upper()
        return "0" * (length - len(hex_str)) + hex_str

    @staticmethod
    def zero_pad(s, length=2):
        if s is None:
            s = ""
        zeros_needed = length - len(s)
        for _ in range(zeros_needed):
            s = '0' + s
        return s


if __name__ == "__main__":
    b = 200
    print(f"b={b}")
    print(f"(int)b={Conv.byte_to_int(b)}")
    print(Conv.to_hex_string(5))
    s = 40000
    print(f"s={s}")
    print(f"(int)s={Conv.short_to_int(s)}")
    print(Conv.to_hex_string(5, length=4))
    i = 3147483648
    print(f"i={i}")
    print(f"(long)i={Conv.int_to_long(i)}")
    print(Conv.to_hex_string(5, length=8))
