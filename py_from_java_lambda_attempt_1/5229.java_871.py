Here is the translation of the Java interface `MutableByteProvider` to a Python class:

```python
class MutableByteProvider:
    def write_byte(self, index: int, value: bytes) -> None:
        """Writes a byte at the specified index."""
        pass  # TO DO: implement I/O operations

    def write_bytes(self, index: int, values: bytes) -> None:
        """Writes a byte array at the specified index."""
        pass  # TO DO: implement I/O operations
```

Note that in Python, we don't have an equivalent concept to Java's `throws IOException` clause. Instead, you would typically raise an exception if an error occurs during I/O operations.

Also, since Python is dynamically typed and doesn't require explicit type declarations like Java does, the types of variables are not explicitly specified here.