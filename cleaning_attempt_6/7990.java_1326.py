class Hasher32:
    def __init__(self):
        pass

    def hash(self, string: str, unsigned_32_bit_mod: int) -> int:
        return self.hash_string_32(string, unsigned_32_bit_mod)

    def hash_string_32(self, string: str, unsigned_32_bit_mod: int) -> int:
        # implement the actual hashing algorithm here
        pass

# Example usage:
hasher = Hasher32()
result = hasher.hash("example", 0xffffffff)
print(result)
