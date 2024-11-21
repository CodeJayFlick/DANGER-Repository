Here is the translation of the Java interface `MemoryFaultHandler` to a Python class:

```python
class MemoryFaultHandler:
    def uninitialized_read(self, address: int, size: int, buf: bytes, buf_offset: int) -> bool:
        """An attempt has been made to read uninitialized memory at the specified address."""
        return True  # Treat data as initialized

    def unknown_address(self, address: int, write: bool) -> bool:
        """Unable to translate the specified address"""
        return False  # Fault was not handled
```

Note that I've used Python's type hints for clarity and consistency. The `uninitialized_read` method returns a boolean indicating whether data should be treated as initialized, while the `unknown_address` method returns a boolean indicating whether the fault was handled or not.