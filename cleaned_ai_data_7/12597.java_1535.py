class MemoryBlockListener:
    def name_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', old_name: str, new_name: str):
        pass  # implement your logic here

    def comment_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', old_comment: str, new_comment: str):
        pass  # implement your logic here

    def read_status_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', is_read: bool) -> None:
        pass  # implement your logic here

    def write_status_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', is_write: bool) -> None:
        pass  # implement your logic here

    def execute_status_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', is_execute: bool) -> None:
        pass  # implement your logic here

    def source_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', old_source: str, new_source: str):
        pass  # implement your logic here

    def source_offset_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', old_offset: int, new_offset: int) -> None:
        pass  # implement your logic here

    def data_changed(self, block: 'ghidra.program.model.mem.MemoryBlock', addr: 'Address', old_data: bytes, new_data: bytes):
        pass  # implement your logic here
