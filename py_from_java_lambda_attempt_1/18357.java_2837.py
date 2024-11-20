Here is the translation of the Java interface `TsFileOutput` to Python:
```python
import io

class TsFileOutput:
    def write(self, b: bytes) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def write(self, b: int) -> None:
        self.write(bytes([b]))

    def write(self, buffer: memoryview) -> None:
        self.write(buffer.tobytes())

    def get_position(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def close(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def wrap_as_stream(self) -> io.IOBase:
        raise NotImplementedError("Subclasses must implement this method")

    def flush(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def truncate(self, size: int) -> None:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I've used the `io` module from Python's standard library to provide some basic file-like functionality. However, since this is an interface and not a concrete implementation, most of the methods are marked as `NotImplementedError`, indicating that subclasses will need to provide their own implementations.

Also, in Python, we don't have direct equivalents for Java's `IOException` or `ByteBuffer`. Instead, I've used Python's built-in exception handling mechanisms (e.g., raising a `ValueError`) and the `memoryview` type from the `buffer` module to represent byte buffers.