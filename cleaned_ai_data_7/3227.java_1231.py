class AddUninitializedMemoryBlockCmd:
    def __init__(self, name: str, comment: str, source: str, start_address: int, length: int,
                 read_permission: bool, write_permission: bool, execute_permission: bool,
                 is_volatile: bool, is_overlay: bool):
        super().__init__(name, comment, source, start_address, length, read_permission,
                         write_permission, execute_permission, is_volatile, is_overlay)

    def create_memory_block(self, memory) -> MemoryBlock:
        return memory.create_uninitialized_block(name=self.name, start=start_address, length=length, is_overlay=is_overlay)
