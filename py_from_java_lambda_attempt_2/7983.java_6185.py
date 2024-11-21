Here is the translation of the Java code into Python:

```Python
class DebugHeader:
    def __init__(self):
        self.header_version = 0
        self.header_length = 0
        self.data_length = 0

    @property
    def header_version(self):
        return self._header_version

    @header_version.setter
    def header_version(self, value):
        self._header_version = value

    @property
    def header_length(self):
        return self._header_length

    @header_length.setter
    def header_length(self, value):
        self._header_length = value

    @property
    def data_length(self):
        return self._data_length

    @data_length.setter
    def data_length(self, value):
        self._data_length = value

    def deserialize(self, reader):
        try:
            self.header_version = int.from_bytes(reader.read(4), 'big')
            self.header_length = int.from_bytes(reader.read(4), 'big')
            self.data_length = int.from_bytes(reader.read(4), 'big')
        except Exception as e:
            raise ValueError("Error deserializing DebugHeader: {}".format(str(e)))

    def __str__(self):
        return str(self.dump())

    def dump(self):
        output = "DebugHeader-------------------------------------------------\n"
        output += f"headerVersion: 0x{self.header_version:x}\n"
        output += f"headerLength: 0x{self.header_length:x}\n"
        output += f"dataLength: 0x{self.data_length:x}\n"
        output += "End DebugHeader---------------------------------------------\n"
        return output
```

This Python code defines a `DebugHeader` class with similar properties and methods as the Java original. The main differences are:

- In Python, we don't need to declare variables or their types before using them.
- We use the `@property` decorator to create getter and setter methods for each property.
- We use the `int.from_bytes()` function from the built-in `int` type in Python to read integers from bytes in big-endian byte order, similar to how Java's `parseUnsignedIntVal()` method works.