class AddBitMappedMemoryBlockCmd:
    def __init__(self, name: str, comment: str, source: str, start_address: int, length: int,
                 read: bool, write: bool, execute: bool, is_volatile: bool, mapped_address: int, 
                 is_overlay: bool):
        self.mapped_address = mapped_address
        super().__init__(name, comment, source, start_address, length, read, write, execute, is_volatile, is_overlay)

    def create_memory_block(self, memory) -> MemoryBlock:
        return memory.create_bit_mapped_block(name=self.name, start=start_address,
                                               mapped_address=mapped_address, length=length, 
                                               is_overlay=is_overlay)
