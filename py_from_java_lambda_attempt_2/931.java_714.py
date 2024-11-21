Here is a translation of the Java interface `DebugHostMemory1` into equivalent Python code:

```python
class DebugHostMemory1:
    def read_bytes(self, context: object, location: str, buffer: bytes, bufferSize: int) -> int:
        pass  # implement this method in your subclass

    def write_bytes(self, context: object, location: str, buffer: bytes, bufferSize: int) -> int:
        pass  # implement this method in your subclass

    def read_pointers(self, context: object, location: str, count: int) -> tuple[int]:
        pass  # implement this method in your subclass

    def write_pointers(self, context: object, location: str, count: int) -> tuple[int]:
        pass  # implement this method in your subclass

    def get_display_string_for_location(self, context: object, location: str, verbose: bool) -> str:
        pass  # implement this method in your subclass
```

Note that I've omitted the `UnknownEx` class and its methods since it's not directly translatable to Python. Additionally, I've used type hints for the function parameters and return types, but you may need to adjust these depending on how you choose to implement the interface.

In particular, the Java `ULONGLONGByReference` type is equivalent to a tuple of two integers in Python (`(int, int)`), since tuples are immutable.