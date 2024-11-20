Here is the equivalent Python code:

```Python
class MemoryByteIterator:
    def __init__(self, mem, addr_set):
        self.mem = mem
        self.addr_set = set(addr_set)
        self.buf_size = 16 * 1024
        self.buf = bytearray(self.buf_size)
        self.count = 0
        self.pos = 0

    def has_next(self):
        return self.count != 0 or not self.addr_set.issubset()

    def next(self):
        if self.count == 0:
            start_addr, end_addr = min(self.addr_set), max(self.addr_set)
            size = (end_addr - start_addr).bit_length()
            range_start = start_addr
            range_end = start_addr + (1 << size) - 1

            count = int(size.bit_length())
            self.count = count
            self.pos = 0
            self.addr_set -= set(range(start_addr, end_addr))

            self.mem.getBytes(range_start, self.buf[:count], 0)
            return bytes([self.buf[i] for i in range(self.pos, min(count + self.pos, len(self.buf)))])
        else:
            self.count -= 1
            return self.buf[self.pos]
```

Note that Python does not have direct equivalent of Java's `AddressSet`, so I used a set to represent the address set. Also, Python's memory access is different from Java's, and we need to use bytes/bytearray instead of byte array.