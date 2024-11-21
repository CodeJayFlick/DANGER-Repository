Here is the translation of the given Java code into equivalent Python:

```Python
class AddByteMappedMemoryBlockCmd:
    def __init__(self, name: str, comment: str, source: str, start_address: int, length: int,
                 read: bool, write: bool, execute: bool, is_volatile: bool, mapped_address: int,
                 byte_mapping_scheme=None, is_overlay=False):
        super().__init__(name, comment, source, start_address, length, read, write, execute, is_volatile, is_overlay)
        self.mapped_address = mapped_address
        self.byte_mapping_scheme = byte_mapping_scheme

    def create_memory_block(self, memory) -> MemoryBlock:
        return memory.create_byte_mapped_block(name=self.name,
                                               start_address=self.start_address,
                                               mapped_address=self.mapped_address,
                                               length=self.length,
                                               byte_mapping_scheme=self.byte_mapping_scheme,
                                               is_overlay=self.is_overlay)
```

Note that Python does not have direct equivalent of Java's `package`, so I did not include it in the translation. Also, Python has no concept of `@Override` as methods are dynamically bound and do not require explicit overriding.