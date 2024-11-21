Here's a translation of the Java code into equivalent Python:

```Python
class AddUninitializedMemoryBlockCmd:
    def __init__(self, name: str, comment: str, source: str, start_address: int, length: int,
                 read_permission: bool, write_permission: bool, execute_permission: bool,
                 is_volatile: bool, is_overlay: bool):
        super().__init__(name, comment, source, start_address, length, read_permission,
                         write_permission, execute_permission, is_volatile, is_overlay)

    def create_memory_block(self, memory) -> MemoryBlock:
        return memory.create_uninitialized_block(name=self.name, start=start_address, length=length, is_overlay=is_overlay)
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of inheritance and method overriding in Python are different from those in Java.

Here's a simple implementation of MemoryBlock class:

```Python
class MemoryBlock:
    def __init__(self):
        pass

    @staticmethod
    def create_uninitialized_block(name: str, start: int, length: int, is_overlay: bool) -> 'MemoryBlock':
        # This method should be implemented based on the actual requirements.
        return None  # For demonstration purposes only.
```

In Python, you can't directly specify a type hint for a static method.