Here is the translation of the Java code into Python:

```Python
class LEB128:
    def __init__(self, offset: int, value: int, byte_length: int):
        self.offset = offset
        self.value = value
        self.byte_length = byte_length

    @staticmethod
    def read_value(reader, is_signed) -> 'LEB128':
        offset = reader.tell()
        value = LEB128.read_as_long(reader, is_signed)
        size = reader.tell() - offset
        return LEB128(offset, value, size)

    @staticmethod
    def read_unsigned_value(reader):
        return LEB128.read_value(reader, False)

    @staticmethod
    def read_signed_value(reader):
        return LEB128.read_value(reader, True)

    @staticmethod
    def read_as_int32(reader) -> int:
        tmp = LEB128.read_as_long(reader, True)
        LEB128._ensure_int32s(tmp)
        return int(tmp)

    @staticmethod
    def read_as_uint32(reader) -> int:
        tmp = LEB128.read_as_long(reader, False)
        LEB128._ensure_int32u(tmp)
        return int(tmp)

    @staticmethod
    def read_as_long(reader: 'BinaryReader', is_signed: bool):
        value = 0
        shift = 0

        while True:
            byte = reader.read_next_unsigned_byte()
            if shift == 70 or (not is_signed and shift == 63 and byte > 1):
                raise IOException("Unsupported LEB128 value, too large to fit in 64bit java long variable")

            # must cast to int before shifting otherwise shift values greater than 32 cause problems
            value |= ((int)(byte & 0x7F)) << shift
            shift += 7

            if (byte & 0x80) == 0:
                break

        if is_signed and shift < Long.SIZE and (byte & 0x40):
            # 0x40 is the new 'high' sign bit since 0x80 is the continuation flag
            value |= (-1 << shift)

        return value

    @staticmethod
    def _ensure_int32u(value: int) -> None:
        if value < 0 or value > Integer.MAX_VALUE:
            raise IOException(f"LEB128 value out of range for java 32 bit unsigned int: {value}")

    @staticmethod
    def _ensure_int32s(value: int) -> None:
        if value < Integer.MIN_VALUE or value > Integer.MAX_VALUE:
            raise IOException(f"LEB128 value out of range for java 32 bit signed int: {value}")


class BinaryReader:
    def __init__(self, provider):
        self.provider = provider
        self.tell() = 0

    def read_next_unsigned_byte(self) -> int:
        # Implement your own byte reading logic here.
        pass

    def tell(self) -> int:
        return self.offset


def main():
    reader = BinaryReader(ByteArrayProvider([1, 2, 3]))  # Initialize the binary reader
    leb128_value = LEB128.read_unsigned_value(reader)
    print(leb128_value.value)


if __name__ == "__main__":
    main()
```

Please note that this is a direct translation of your Java code into Python. The logic remains the same, but you will need to implement the `read_next_unsigned_byte` method in the `BinaryReader` class according to how you want to read bytes from your file or stream.

Also, I have used Python's built-in types for integers (`int`) and longs (`long`).