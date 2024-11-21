Here is a translation of the Java interface `MemBufferAdapter` into equivalent Python code:

```Python
class MemBufferAdapter:
    def get_bytes(self, buffer: bytes, address_offset: int) -> int:
        pass  # Implement this method in your subclass

    def get_byte(self, offset: int) -> int:
        if self.get_bytes(bytearray(1), offset) < 1:
            raise MemoryAccessException("Couldn't get requested byte")
        return bytearray(1)[0]

    def get_bytes(self, b: bytes, offset: int) -> int:
        return self.get_bytes(memoryview(b).cast('b'), offset)

    def get_bytes_in_full(self, offset: int, length: int) -> memoryview:
        buf = memoryview(bytearray(length))
        if self.get_bytes(buf.cast('B').tobytes(), offset) != len(buf):
            raise MemoryAccessException("Could not read enough bytes")
        return buf

    def get_short(self, offset: int) -> int:
        return struct.unpack('<h', self.get_bytes_in_full(offset, 2).tobytes())[0]

    def get_int(self, offset: int) -> int:
        return struct.unpack('<i', self.get_bytes_in_full(offset, 4).tobytes())[0]

    def get_long(self, offset: int) -> int:
        return struct.unpack('<q', self.get_bytes_in_full(offset, 8).tobytes())[0]

    def get_big_integer(self, offset: int, size: int, signed: bool) -> BigInteger:
        buf = self.get_bytes_in_full(offset, size)
        if not signed:
            buf = buf.byteswap()
        return BigInteger(buf.tobytes())
```

Note that this is a direct translation of the Java code into Python. In particular:

* The `getByte` method now returns an integer instead of a byte.
* The `getBytesInFull` method now returns a memoryview, which is equivalent to a ByteBuffer in Java.
* The `getShort`, `getInt`, and `getLong` methods use the `struct` module to unpack the bytes into integers or longs. This is similar to how these methods would be implemented using NIO in Java.

You will need to implement the `get_bytes` method in your subclass, as it was an abstract method in the original Java code.