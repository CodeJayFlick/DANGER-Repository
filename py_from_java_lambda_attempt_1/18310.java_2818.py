Here is the equivalent Python code:

```Python
class PublicBAOS:
    def __init__(self):
        self.buf = bytearray()

    def getBuf(self):
        return self.buf

    def writeTo(self, out):
        out.write(self.buf)

    def reset(self):
        self.buf = bytearray()
        self.count = 0

    @property
    def size(self):
        return len(self.buf)

    def truncate(self, size):
        self.buf = self.buf[:size]
```

Note that Python does not have a direct equivalent to Java's `ByteArrayOutputStream`. Instead, we use the built-in `bytearray` type. The rest of the code is translated as follows:

- The constructor (`__init__`) initializes an empty bytearray.
- The `getBuf` method returns the current bytearray.
- The `writeTo` method writes the contents of the bytearray to another output stream (in this case, a file or socket).
- The `reset` method resets the bytearray and its count to zero. This effectively discards any accumulated data in the buffer.
- The `size` property returns the length of the bytearray.
- The `truncate` method truncates the bytearray at the specified size.

Note that Python does not have a direct equivalent to Java's `@Override`, so we do not include it here.