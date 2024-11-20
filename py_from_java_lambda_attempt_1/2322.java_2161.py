Here is the translation of the Java interface into a Python class:

```Python
class BytesPcodeExecutorStateMixin:
    def from_constant(self, constant: int) -> object:
        pass  # Implement this method in your subclass

    def offset_to_long(self, offset: object) -> int:
        pass  # Implement this method in your subclass

    def to_bytes(self, val: object, size: int) -> bytes:
        pass  # Implement this method in your subclass

    def from_bytes(self, data: bytes) -> object:
        pass  # Implement this method in your subclass
```

Note that the Python code does not have direct equivalents for Java's generics (i.e., `<A, T>`), so I've left those out.