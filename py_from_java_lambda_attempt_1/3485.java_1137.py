Here is the equivalent Python code:

```Python
class MemoryInputStream:
    def __init__(self, mem, set):
        self.it = iter(mem.get_bytes(set))

    def read(self) -> int:
        try:
            if self.it:
                return next(self.it)
            else:
                return -1
        except StopIteration:
            raise IOError("End of file reached")
```

Note that Python does not have direct equivalents to Java's `InputStream` and `IOException`. Instead, we use the built-in `iter` function to create an iterator over a sequence (in this case, bytes from memory), and the `try/except` block is used to handle exceptions.