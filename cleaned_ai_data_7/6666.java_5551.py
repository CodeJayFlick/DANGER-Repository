class BytesAndDisassembly:
    def __init__(self, bytes: str, disassembly: str):
        self.bytes = bytes
        self.disassembly = disassembly

    @property
    def bytes(self) -> str:
        return self._bytes

    @bytes.setter
    def bytes(self, value: str):
        self._bytes = value

    @property
    def disassembly(self) -> str:
        return self._disassembly

    @disassembly.setter
    def disassembly(self, value: str):
        self._disassembly = value

    def __eq__(self, other):
        if not isinstance(other, BytesAndDisassembly):
            return False
        return (other.bytes == self.bytes) and (other.disassembly == self.disassembly)

    def __hash__(self):
        hash_value = 17
        hash_value *= 31 + hash(self.bytes)
        hash_value *= 31 + hash(self.disassembly)
        return hash_value

# Example usage:
bytes_and_dis = BytesAndDisassembly("example bytes", "disassembled code")
print(bytes_and_dis.bytes)  # prints: example bytes
print(bytes_and_dis.disassembly)  # prints: disassembled code
