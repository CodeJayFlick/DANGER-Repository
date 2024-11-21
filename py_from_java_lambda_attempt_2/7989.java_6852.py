Here is the translation of the Java code to Python:
```python
class Hasher:
    def hash(self, string: str, unsigned_32_bit_mod: int) -> int:
        return self.hash_string32(string, unsigned_32_bit_mod) & 0xffff

    def hash_string32(self, string: str, unsigned_32_bit_mod: int) -> int:
        bytes = string.encode()
        reader = PdbByteReader(bytes)
        count = len(bytes)
        # Processing 4 bytes at a time.
        hash = 0

        while count >= 4:
            count -= 4
            hash ^= reader.parse_unsigned_int_val()

        if bytes.length - reader.get_index() >= 2:
            hash ^= reader.parse_unsigned_short_val()
        elif bytes.length - reader.get_index() == 1:
            hash ^= reader.parse_unsigned_byte_val()

        hash |= 0x20202020  # to-lower mask
        hash ^= (hash >> 11)
        # Mask down to 32-bits.
        hash &= 0xffffffff
        # Apply modulus.
        return (hash ^ (hash >> 16)) % unsigned_32_bit_mod

class PdbByteReader:
    def __init__(self, bytes: bytearray):
        self.bytes = bytes
        self.index = 0

    def parse_unsigned_int_val(self) -> int:
        val = 0
        for i in range(4):
            val |= (int.from_bytes(self.bytes[self.index:i+1], 'big') << (24 - i*8))
            self.index += 1
        return val

    def parse_unsigned_short_val(self) -> int:
        val = int.from_bytes(self.bytes[self.index:self.index+2], 'big')
        self.index += 2
        return val

    def parse_unsigned_byte_val(self) -> int:
        val = int.from_bytes(self.bytes[self.index:self.index+1], 'big')
        self.index += 1
        return val

    def get_index(self) -> int:
        return self.index
```
Note that I had to create a separate `PdbByteReader` class in Python, as the original Java code used an existing `PdbByteReader` class. In this translation, I implemented the necessary methods for reading unsigned integers, shorts, and bytes from the byte array.

Also, keep in mind that some parts of the original code may not be directly translatable to Python due to differences in language syntax or semantics.