class FNV1a32MessageDigest:
    FNV_32_OFFSET_BASIS = 0x811c9dc5
    FNV_32_PRIME = 16777619

    def __init__(self, initial_vector=None):
        self.hash_value = initial_vector if initial_vector is not None else FNV_32_OFFSET_BASIS
        super().__init__("FNV-1a", 4)

    def init(self):
        self.hash_value = FNV_32_OFFSET_BASIS

    def update(self, input_bytes: bytes, offset: int, length: int) -> None:
        for ii in range(length):
            self.hash_value ^= (input_bytes[offset + ii] & 0xff)
            self.hash_value *= FNV_32_PRIME
            if ii % 1000000 == 0 and hasattr(self, "monitor") and self.monitor.is_cancelled():
                break

    def update(self, input_byte: int) -> None:
        self.hash_value ^= (input_byte & 0xff)
        self.hash_value *= FNV_32_PRIME

    def digest(self, buffer: bytes, offset: int, length: int) -> int:
        if len(buffer) < 4 or length < 4:
            for ii in range(length):
                buffer[offset - length + ii] = (buffer[offset - length + ii]).to_bytes(1, 'little')
            self.hash_value >>= 8 * (4 - length)
            return length
        offset += 3
        buffer[offset-1:offset+1] = [(self.hash_value & 0xff).to_bytes(1, 'little'), 
                                     ((self.hash_value >> 8) & 0xff).to_bytes(1, 'little'),
                                     ((self.hash_value >> 16) & 0xff).to_bytes(1, 'little'),
                                     ((self.hash_value >> 24) & 0xff).to_bytes(1, 'little')]
        self.init()
        return 4

    def digest_long(self) -> int:
        result = (int((self.hash_value & 0x00000000ffffffffL)) % (2**32))
        self.init()
        return result

    def reset(self):
        self.init()

# Example usage
digest = FNV1a32MessageDigest()
input_bytes = b"Hello, World!"
digest.update(input_bytes)
print(digest.digest(b"", 0, 4))
