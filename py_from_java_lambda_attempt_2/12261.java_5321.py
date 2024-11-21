Here is the translation of the Java code to Python:
```
class CustomFormat:
    def __init__(self, data_type: bytes, format_bytes: bytes):
        self.data_type = data_type
        self.format = format_bytes

    @property
    def data_type(self) -> bytes:
        return self._data_type

    @data_type.setter
    def data_type(self, value: bytes):
        self._data_type = value

    @property
    def format(self) -> bytes:
        return self._format

    @format.setter
    def format(self, value: bytes):
        self._format = value

# Example usage:
if __name__ == "__main__":
    data_type = b"example_data_type"
    format_bytes = b"\x01\x02\x03\x04"
    custom_format = CustomFormat(data_type, format_bytes)
    print(custom_format.data_type)  # prints: example_data_type
    print(custom_format.format)  # prints: b'\x01\x02\x03\x04'
```
Note that I used the `@property` decorator to create read-only properties for the `data_type` and `format` attributes, which is similar to Java's getter/setter methods.