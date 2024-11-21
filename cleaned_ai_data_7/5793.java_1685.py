class MemoryBlockDiff:
    def __init__(self, memory1: 'Memory', memory2: 'Memory', range: 'AddressRange'):
        super().__init__(memory1.getBlock(range.getMinAddress()), memory2.getBlock(range.getMinAddress()))
        self.memory1 = memory1
        self.memory2 = memory2
        self.range = range

    def get_memory1(self):
        return self.memory1

    def get_memory2(self):
        return self.memory2

    def get_address_range(self):
        return self.range


class Memory:
    pass


class AddressRange:
    def __init__(self, min_address: int):
        self.minAddress = min_address
