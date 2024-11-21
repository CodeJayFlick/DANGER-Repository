Here is the equivalent Python code:

```Python
class BytesSupplier:
    def __init__(self):
        self.buf = None
        self.value = None
        self.obj = None

    def from_bytes(self, buf: bytes) -> None:
        self.buf = buf

    def from_string(self, value: str) -> None:
        self.value = value

    def from_object(self, obj) -> None:
        self.obj = obj

    def get_as_bytes(self) -> bytes:
        if not self.buf:
            if not self.value:
                import json
                self.value = json.dumps(obj)
            self.buf = self.value.encode('utf-8')
        return self.buf

    def get_as_string(self) -> str:
        if not self.value:
            if self.obj is None and not self.buf:
                self.value = self.buf.decode('utf-8') + '\n'
            elif self.obj is not None:
                import json
                self.value = json.dumps(obj)
        return self.value

    def get_as_object(self) -> object:
        if self.obj is not None:
            return self.obj
        elif self.value is not None:
            try:
                return eval('"' + self.value + '"')
            except Exception as e:
                print(f"Error: {e}")
        else:
            return self.buf

    def to_byte_buffer(self) -> bytes:
        if self.buf:
            import array
            return memoryview(array.array('b', self.get_as_bytes()))
```

Please note that Python does not have direct equivalent of Java's `ByteBuffer` and `JsonUtils`. The above code uses built-in Python functions for JSON serialization (`json.dumps`) and string encoding/decoding.