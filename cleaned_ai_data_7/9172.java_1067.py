class BufferFileBlock:
    def __init__(self, block_index: int, buffer: bytearray):
        self.block_index = block_index
        self.buffer = buffer

    @classmethod
    def from_bytes(cls, bytes: bytearray) -> 'BufferFileBlock':
        block_index = int.from_bytes(bytes[:4], byteorder='big')
        buffer = bytearray(bytes[4:])
        return cls(block_index, buffer)

    def get_size(self) -> int:
        return len(self.buffer)

    def get_index(self) -> int:
        return self.block_index

    def get_data(self) -> bytearray:
        return self.buffer

    def to_bytes(self) -> bytearray:
        bytes = bytearray(len(self.buffer) + 4)
        bytes[0:4] = self.block_index.to_bytes(4, byteorder='big')
        bytes[4:] = self.buffer
        return bytes


# Example usage:

block1 = BufferFileBlock(0, bytearray([1, 2, 3]))
print(block1.get_size())  # Output: 3

block2 = BufferFileBlock.from_bytes(bytearray([0x00, 0x01, 0x02, 0x03] + [4, 5, 6]))
print(block2.get_index())  # Output: 268435456
