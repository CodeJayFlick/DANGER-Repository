class GDataConverter:
    def get_short(self, b: bytes) -> int:
        if len(b) < 2:
            raise IndexError("Byte array size must be at least 2")
        return (b[1] << 8 | b[0]) & 0xFFFF

    def get_short(self, b: bytes, offset: int) -> int:
        if offset + 2 > len(b):
            raise IndexError("Byte array size is less than offset+2")
        return (b[offset+1] << 8 | b[offset]) & 0xFFFF

    def get_int(self, b: bytes) -> int:
        if len(b) < 4:
            raise IndexError("Byte array size must be at least 4")
        return (b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]) & 0xFFFFFFFF

    def get_int(self, b: bytes, offset: int) -> int:
        if offset + 4 > len(b):
            raise IndexError("Byte array size is less than offset+4")
        return (b[offset+3] << 24 | b[offset+2] << 16 | b[offset+1] << 8 | b[offset]) & 0xFFFFFFFF

    def get_long(self, b: bytes) -> int:
        if len(b) < 8:
            raise IndexError("Byte array size must be at least 8")
        return (b[7] << 56 | b[6] << 48 | b[5] << 40 | b[4] << 32 |
                b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]) & 0xFFFFFFFFFFFFFFFF

    def get_long(self, b: bytes, offset: int) -> int:
        if offset + 8 > len(b):
            raise IndexError("Byte array size is less than offset+8")
        return (b[offset+7] << 56 | b[offset+6] << 48 | b[offset+5] << 40 |
                b[offset+4] << 32 | b[offset+3] << 24 | b[offset+2] << 16 |
                b[offset+1] << 8 | b[offset]) & 0xFFFFFFFFFFFFFFFF

    def get_value(self, b: bytes, size: int) -> int:
        if len(b) < size:
            raise IndexError("Byte array size is less than size")
        return (b[size-1] << ((size - 1) * 8) | 
                (int.from_bytes(b[:size], 'big') >> ((size - 1) * 8)) & 0xFFFFFFFFFFFFFFFF)

    def get_value(self, b: bytes, offset: int, size: int) -> int:
        if offset + size > len(b):
            raise IndexError("Byte array size is less than offset+size")
        return (b[offset+size-1] << ((size - 1) * 8) | 
                (int.from_bytes(b[offset:offset+size], 'big') >> ((size - 1) * 8)) & 0xFFFFFFFFFFFFFFFF)

    def get_bytes(self, value: int, b: bytearray = bytearray()) -> None:
        if len(b) < 2:
            raise IndexError("Byte array size must be at least 2")
        b[1] = (value >> 8) & 0xFF
        b[0] = value & 0xFF

    def get_bytes(self, value: int, offset: int, b: bytearray = bytearray()) -> None:
        if len(b) < 2 or offset + 2 > len(b):
            raise IndexError("Byte array size is less than offset+2")
        b[offset+1] = (value >> 8) & 0xFF
        b[offset] = value & 0xFF

    def get_bytes(self, value: int, b: bytearray = bytearray()) -> None:
        if len(b) < 4:
            raise IndexError("Byte array size must be at least 4")
        b[3] = (value >> 24) & 0xFF
        b[2] = (value >> 16) & 0xFF
        b[1] = (value >> 8) & 0xFF
        b[0] = value & 0xFF

    def get_bytes(self, value: int, offset: int, b: bytearray = bytearray()) -> None:
        if len(b) < 4 or offset + 4 > len(b):
            raise IndexError("Byte array size is less than offset+4")
        b[offset+3] = (value >> 24) & 0xFF
        b[offset+2] = (value >> 16) & 0FF
        b[offset+1] = (value >> 8) & 0xFF
        b[offset] = value & 0xFF

    def get_bytes(self, value: int, size: int, b: bytearray = bytearray()) -> None:
        if len(b) < size or offset + size > len(b):
            raise IndexError("Byte array size is less than offset+size")
        for i in range(size-1, -1, -1):
            b[offset+i] = (value >> ((size-i)*8)) & 0xFF

    def get_bytes(self, value: int) -> bytearray:
        return self.get_bytes(value).copy()

    def put_short(self, b: bytearray, value: int) -> None:
        if len(b) < 2:
            raise IndexError("Byte array size must be at least 2")
        b[1] = (value >> 8) & 0xFF
        b[0] = value & 0xFF

    def put_short(self, b: bytearray, offset: int, value: int) -> None:
        if len(b) < 2 or offset + 2 > len(b):
            raise IndexError("Byte array size is less than offset+2")
        b[offset+1] = (value >> 8) & 0xFF
        b[offset] = value & 0FF

    def put_int(self, b: bytearray, value: int) -> None:
        if len(b) < 4:
            raise IndexError("Byte array size must be at least 4")
        b[3] = (value >> 24) & 0xFF
        b[2] = (value >> 16) & 0FF
        b[1] = (value >> 8) & 0FF
        b[0] = value & 0FF

    def put_int(self, b: bytearray, offset: int, value: int) -> None:
        if len(b) < 4 or offset + 4 > len(b):
            raise IndexError("Byte array size is less than offset+4")
        b[offset+3] = (value >> 24) & 0FF
        b[offset+2] = (value >> 16) & 0xFF
        b[offset+1] = (value >> 8) & 0FF
        b[offset] = value & 0FF

    def put_long(self, b: bytearray, value: int) -> None:
        if len(b) < 8:
            raise IndexError("Byte array size must be at least 8")
        for i in range(7, -1, -1):
            b[i] = (value >> ((7-i)*8)) & 0FF

    def put_long(self, b: bytearray, offset: int, value: int) -> None:
        if len(b) < 8 or offset + 8 > len(b):
            raise IndexError("Byte array size is less than offset+8")
        for i in range(7, -1, -1):
            b[offset+i] = (value >> ((7-i)*8)) & 0FF
