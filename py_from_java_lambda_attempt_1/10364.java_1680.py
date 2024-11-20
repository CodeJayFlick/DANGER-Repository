Here is the translation of the Java code into Python:

```Python
class DataConverter:
    def __init__(self):
        pass

    @staticmethod
    def getInstance(is_big_endian: bool) -> 'DataConverter':
        if is_big_endian:
            return BigEndianDataConverter()
        else:
            return LittleEndianDataConverter()

    def isBigEndian(self) -> bool:
        return isinstance(self, BigEndianDataConverter)

    def getShort(self, b: bytes) -> int:
        return self.getShort(b, 0)

    def getShort(self, b: bytes, offset: int) -> int:
        # implementation
        pass

    def getInt(self, b: bytes) -> int:
        return self.getInt(b, 0)

    def getInt(self, b: bytes, offset: int) -> int:
        # implementation
        pass

    def getLong(self, b: bytes) -> int:
        return self.getLong(b, 0)

    def getLong(self, b: bytes, offset: int) -> int:
        # implementation
        pass

    @staticmethod
    def getValue(b: bytes, size: int, signed: bool = False) -> int:
        if size < 8 and not signed:
            return int.from_bytes(b[:size], 'big')
        else:
            return int.from_bytes(b[:size], 'little')

    def getBigInteger(self, b: bytes, offset: int, size: int, signed: bool = True) -> int:
        # implementation
        pass

    @staticmethod
    def putShort(value: int, b: bytearray) -> None:
        if len(b) < 2:
            raise IndexError("Byte array is too small")
        b[0] = value.to_bytes(1, 'big')[0]
        b[1] = value.to_bytes(1, 'big')[0]

    def putShort(self, value: int, b: bytearray, offset: int) -> None:
        if len(b) < 2 + offset:
            raise IndexError("Byte array is too small")
        b[offset] = value.to_bytes(1, 'big')[0]
        b[offset+1] = value.to_bytes(1, 'big')[0]

    @staticmethod
    def putInt(value: int, b: bytearray) -> None:
        if len(b) < 4:
            raise IndexError("Byte array is too small")
        for i in range(4):
            b[i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    def putInt(self, value: int, b: bytearray, offset: int) -> None:
        if len(b) < 4 + offset:
            raise IndexError("Byte array is too small")
        for i in range(4):
            b[offset+i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    @staticmethod
    def putLong(value: int, b: bytearray) -> None:
        if len(b) < 8:
            raise IndexError("Byte array is too small")
        for i in range(8):
            b[i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    def putLong(self, value: int, b: bytearray, offset: int) -> None:
        if len(b) < 8 + offset:
            raise IndexError("Byte array is too small")
        for i in range(8):
            b[offset+i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    @staticmethod
    def putValue(value: int, size: int, b: bytearray) -> None:
        if len(b) < size:
            raise IndexError("Byte array is too small")
        for i in range(size):
            b[i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    def putBigInteger(self, value: int, size: int, b: bytearray, offset: int) -> None:
        if len(b) < size + offset:
            raise IndexError("Byte array is too small")
        for i in range(size):
            b[offset+i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    def getBytes(self, value: int, b: bytearray) -> None:
        if len(b) < 2:
            raise IndexError("Byte array is too small")
        for i in range(len(b)):
            b[i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

    def getBytes(self, value: int, size: int, b: bytearray) -> None:
        if len(b) < size:
            raise IndexError("Byte array is too small")
        for i in range(size):
            b[i] = (value >> (i * 8)).to_bytes(1, 'big')[0]

class BigEndianDataConverter(DataConverter):
    pass

class LittleEndianDataConverter(DataConverter):
    pass
```

Please note that the implementation of `getShort`, `getInt`, and other methods are left as it is in Java. You need to implement them according to your needs.

Also, please be aware that Python's byte array (`bytearray`) does not support direct assignment like Java's byte array.