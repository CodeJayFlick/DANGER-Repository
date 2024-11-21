Here is the translation of the Java interface into a Python class:

```Python
class LiveMemoryHandler:
    def __init__(self):
        pass

    def clear_cache(self):
        # Implement your logic here for clearing cache.
        pass

    def get_byte(self, addr: 'Address') -> bytes:
        try:
            return b''  # Replace with actual byte value or raise exception
        except Exception as e:
            raise MemoryAccessException(str(e))

    def get_bytes(self, address: 'Address', buffer: bytearray, start_index: int, size: int) -> int:
        try:
            num_bytes = 0  # Replace with actual number of bytes retrieved.
            return num_bytes
        except Exception as e:
            raise MemoryAccessException(str(e))

    def put_byte(self, address: 'Address', value: bytes):
        try:
            pass  # Implement your logic here for putting byte into memory.
        except Exception as e:
            raise MemoryAccessException(str(e))

    def put_bytes(self, address: 'Address', source: bytearray, start_index: int, size: int) -> int:
        try:
            num_bytes = 0  # Replace with actual number of bytes written to memory.
            return num_bytes
        except Exception as e:
            raise MemoryAccessException(str(e))

    def add_live_memory_listener(self, listener):
        pass

    def remove_live_memory_listener(self, listener):
        pass


class Address:
    def __init__(self, value: int):
        self.value = value

    def get_value(self) -> int:
        return self.value
```

Note that the Python code does not have direct equivalent of Java's `throws` keyword. Instead, exceptions are raised using the built-in `raise` statement.

Also note that I did not implement all methods as they were in the original interface because some of them seem to be missing implementation details and might require additional context or information from you about how these methods should behave.