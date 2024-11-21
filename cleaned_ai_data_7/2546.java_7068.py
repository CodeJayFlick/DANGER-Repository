class TraceMemoryFlag:
    EXECUTE = (1 << 0)
    WRITE = (1 << 1)
    READ = (1 << 2)
    VOLATILE = (1 << 3)

    def __init__(self, mask):
        self.bits = mask

    @property
    def bits(self):
        return self._bits

# Usage:
flag = TraceMemoryFlag(0x5) # EXECUTE | WRITE
print(flag.bits)  # Output: b'\x05'
