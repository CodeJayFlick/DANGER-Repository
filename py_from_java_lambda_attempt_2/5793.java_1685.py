Here is the translation of the given Java code into Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `Memory` and `AddressRange`. I've created two new classes (`Memory`, `AddressRange`) in the above code. The actual implementation of these classes would depend on your specific requirements.

Also, please be aware that this is a translation from Java to Python, but it might not work as-is if you're trying to use some sort of reverse-engineering or disassembly tool like GHIDRA (which seems to be the case based on the original code).