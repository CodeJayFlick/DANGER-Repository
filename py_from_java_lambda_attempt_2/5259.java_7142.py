Here is the translation of the Java code into Python:

```Python
class GUID:
    SIZEOF = 16

    def __init__(self, data1: int, data2: short, data3: short, data4: bytes):
        self.data1 = data1
        self.data2 = data2
        self.data3 = data3
        self.data4 = data4

    @classmethod
    def from_string(cls, guid_string: str) -> 'GUID':
        parts = get_guid_parts(guid_string)
        return cls(int(parts[0], 16), int.from_bytes(parts[1].encode(), byteorder='big'), 
                   int.from_bytes(parts[2].encode(), byteorder='big'), bytes.fromhex(''.join([parts[3][i:i+2] for i in range(0, len(parts[3]), 2)])))

    @classmethod
    def from_binary_reader(cls, reader):
        data1 = int.from_bytes(reader.read(4), byteorder='little')
        data2 = int.from_bytes(reader.read(2), byteorder='little') & 0xFFFF
        data3 = int.from_bytes(reader.read(2), byteorder='little') & 0xFFFF
        data4 = reader.read(8)
        return cls(data1, data2, data3, data4)

    @classmethod
    def from_memory_buffer(cls, buf):
        data1bytes = bytearray(4)
        data2bytes = bytearray(2)
        data3bytes = bytearray(2)
        data4bytes = bytearray(8)

        offset = 0

        for i in range(len(data1bytes)):
            data1bytes[i] = buf.get_byte(offset++)
        for i in range(len(data2bytes)):
            data2bytes[i] = buf.get_byte(offset++)
        for i in range(len(data3bytes)):
            data3bytes[i] = buf.get_byte(offset++)
        for i in range(len(data4bytes)):
            data4bytes[i] = buf.get_byte(offset++)

        dc = DataConverter(buf.is_big_endian())
        return cls(dc.int_from_bytes(data1bytes), dc.short_from_bytes(data2bytes), 
                   dc.short_from_bytes(data3bytes), bytes(data4bytes))

    def __str__(self):
        sb = f"{Conv.hex_string(self.data1)}-{Conv.hex_string((self.data2 & 0xFFFF))}-{Conv.hex_string((self.data3 & 0xFFFF))}-"
        for i in range(8):
            sb += Conv.hex_string([self.data4[i]])
        return sb

    def get_data1(self) -> int:
        return self.data1

    def get_data2(self) -> int:
        return self.data2

    def get_data3(self) -> int:
        return self.data3

    def get_data4(self) -> bytes:
        return self.data4
```

Please note that Python does not have direct equivalent of Java's `int`, `short` and `byte[]`. So, I used Python's built-in types like `int`, `bytes` to represent these. Also, the conversion from hexadecimal string to integer is done using Python's built-in functions.