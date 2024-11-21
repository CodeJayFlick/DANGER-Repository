import json

class BytesSupplier:
    def __init__(self):
        pass

    @property
    def as_bytes(self) -> bytes:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def as_string(self) -> str:
        return self.as_bytes.decode('utf-8')

    @property
    def as_object(self) -> object:
        return self

class BytesSupplierImpl(BytesSupplier):
    _buf: bytes | None = None

    def __init__(self, buf: bytes | str | object):
        if isinstance(buf, bytes):
            self._buf = buf
        elif isinstance(buf, str):
            self._buf = buf.encode('utf-8')
        else:
            raise ValueError("Invalid input type")

    @property
    def as_bytes(self) -> bytes:
        return self._buf

def wrap(buf: bytes | str | object) -> BytesSupplier:
    if isinstance(buf, (bytes, str)):
        return BytesSupplierImpl(buf)
    elif isinstance(buf, dict):
        # Assume buf is a JSON object and convert it to bytes
        return BytesSupplierImpl(json.dumps(buf).encode('utf-8'))
    else:
        raise ValueError("Invalid input type")

# Example usage:
buf = wrap(b"Hello")
print(buf.as_string)  # Output: "Hello"

buf = wrap({"key": "value"})
print(buf.as_string)  # Output: '{"key": "value"}'
