Here is the translation of the given Java code into Python:

```Python
class CRC64:
    poly = 0xC96C5795D7870F42
    crc_table = [0] * 256

    def __init__(self):
        for b in range(256):
            r = b
            for i in range(8):
                if (r & 1) == 1:
                    r = (r >> 1) ^ self.poly
                else:
                    r >>= 1
            self.crc_table[b] = r

    def update(self, buf, off, len):
        end = off + len
        while off < end:
            self.crc = self.crc_table[(buf[off] ^ int.from_bytes([self.crc], 'big')) & 0xFF] ^ (int.from_bytes([self.crc], 'big') >> 8)
            off += 1

    def finish(self):
        value = ~self.crc
        self.crc = -1
        return value


# Example usage:
crc64 = CRC64()
buf = bytes(range(256))
off, len = 0, len(buf)
while off < len:
    crc64.update(buf, off, min(off + 255, len) - off + 1)
print(crc64.finish())
```

This Python code defines a class `CRC64` that implements the CRC-64 algorithm. The constructor initializes the polynomial and the lookup table for the CRC calculation. The `update` method updates the CRC value based on the given buffer data, and the `finish` method returns the final CRC value after updating all bytes in the buffer.

Note: Python's built-in bitwise operations are used to implement the CRC-64 algorithm.