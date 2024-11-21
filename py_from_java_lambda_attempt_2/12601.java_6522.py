Here is the translation of the Java code into Python:

```Python
class MemoryBufferImpl:
    def __init__(self, mem, addr):
        self.mem = mem
        self.start_addr = addr
        self.buffer_size = 1024
        self.threshold = buffer_size // 100
        self.converter = GhidraDataConverter(mem.is_big_endian())
        self.position(addr)

    @classmethod
    def clone(cls, mem, start_addr):
        return cls(mem, start_addr, buffer_size)

    def advance(self, displacement):
        addr = self.start_addr.add(displacement)
        self.position(addr)

    def position(self, addr):
        if min_offset <= max_offset:
            diff = addr - self.start_addr
            if 0 <= diff < threshold:
                self.start_addr = addr
                min_offset -= int(diff)
                max_offset -= int(diff)
                start_addr_index += int(diff)
                return

        self.start_addr = addr
        start_addr_index = 0
        min_offset = 0
        max_offset = -1

    def get_byte(self, offset):
        if min_offset <= offset <= max_offset:
            return buffer[start_addr_index + offset]
        try:
            addr = self.start_addr.add(offset)
            n_read = mem.get_bytes(addr, buffer, 0, len(buffer))
            start_addr_index -= int(offset)
            min_offset = offset
            max_offset = offset + n_read - 1
            return buffer[0]
        except Exception as e:
            raise MemoryAccessException(str(e))

    def get_address(self):
        return self.start_addr

    def get_memory(self):
        return self.mem

    def get_bytes(self, b, offset):
        if min_offset <= offset and (len(b) + offset) <= max_offset:
            buffer[start_addr_index + offset:start_addr_index + len(b)] = b
            return len(b)
        try:
            return mem.get_bytes(self.start_addr.add(offset), b)
        except Exception as e:
            return 0

    def is_big_endian(self):
        return self.mem.is_big_endian()

    def get_short(self, offset):
        return converter.get_short(self, offset)

    def get_int(self, offset):
        return converter.get_int(self, offset)

    def get_long(self, offset):
        return converter.get_long(self, offset)
```

Note: The `GhidraDataConverter` class is not provided in the Java code. It seems to be a custom class that converts between different data formats (e.g., big-endian and little-endian). You would need to implement this class or replace it with your own equivalent functionality.

Also, some exceptions are thrown from within methods (`AddressOutOfBoundsException`, `MemoryAccessException`), but Python does not have direct equivalents for these. Instead, you can use built-in exception types like `ValueError` or create custom exceptions if needed.