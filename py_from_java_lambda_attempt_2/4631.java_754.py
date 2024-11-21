Here is the translation of the given Java code into equivalent Python:

```Python
class CoffSymbolAuxFilename:
    def __init__(self):
        self.filename = None
        self.unused = None

    def from_binary_reader(self, reader):
        try:
            self.filename = reader.read_bytes(CoffConstants.FILE_NAME_LENGTH)
            self.unused = reader.read_bytes(4)
        except Exception as e:
            raise IOException(str(e))

    @property
    def filename(self):
        return self.filename.decode('utf-8') if self.filename else None

    @filename.setter
    def filename(self, value):
        self.filename = value.encode()

    @property
    def unused(self):
        return self.unused

    @unused.setter
    def unused(self, value):
        self.unused = value

class CoffSymbolAux:
    pass  # This class is not implemented in the given Java code. It's just an interface.

# Constants for file name length and other values can be defined here.
CoffConstants = {
    'FILE_NAME_LENGTH': 8
}
```

Note that Python does not have direct equivalent of Java classes, interfaces or exceptions. The above translation is based on understanding the purpose of each part of the given code in context of Python programming language.