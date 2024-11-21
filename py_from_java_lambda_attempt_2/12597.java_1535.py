Here is the translation of the Java interface `MemoryBlockListener` into a Python class:

```Python
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
```

Note that the Python code does not have direct equivalent of Java's `public` access modifier. In Python, you can use a class or function without any special declaration to make it accessible from outside the class.

Also note that in Python, we don't need to specify types for method parameters like we do in Java. The type hinting is used only for documentation and static analysis purposes.