Here is the equivalent Python code:

```Python
class ResourceDirectoryString:
    def __init__(self, reader, index):
        self.length = reader.read_short(index)
        self.name_string = reader.read_ascii_string(index + 2)  # assuming SIZEOF_SHORT is 2 bytes
        if len(self.name_string) != self.length:
            raise ValueError("name string length != length")

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        self._length = value

    @property
    def name_string(self):
        return self._name_string

    @name_string.setter
    def name_string(self, value):
        if len(value) != self.length:
            raise ValueError("name string length != length")
        self._name_string = value

def to_data_type(self):
    struct = {"Length": self.length, "NameString": self.name_string}
    return struct

def __str__(self):
    return self.name_string
```

Note that Python does not have direct equivalents for Java's `StructConverter` and `DataType`, so I've replaced them with simple dictionaries. Also, the equivalent of Java's constructor is a special method called `__init__`.