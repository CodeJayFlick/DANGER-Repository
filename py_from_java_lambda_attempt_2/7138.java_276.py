Here is the translation of the given Java code into Python:

```Python
class MethodIDItem:
    def __init__(self, reader):
        self._file_offset = reader.get_pointer_index()
        self.class_index = reader.read_next_short()
        self.proto_index = reader.read_next_short()
        self.name_index = reader.read_next_int()

    @property
    def file_offset(self):
        return self._file_offset

    @property
    def class_index(self):
        return self.class_index

    @property
    def proto_index(self):
        return self.proto_index

    @property
    def name_index(self):
        return self.name_index


class BinaryReader:
    def get_pointer_index(self):
        pass  # implement this method as needed

    def read_next_short(self):
        pass  # implement this method as needed

    def read_next_int(self):
        pass  # implement this method as needed
```

Note that the `BinaryReader` class is not fully implemented in Python, as it was a part of Java's `java.io` package. You would need to create your own implementation for reading binary data in Python.

Also note that there are no equivalent methods like `toDataType()` and `setCategoryPath()` from Java's `StructConverterUtil` class available in Python. If you want similar functionality, you might consider using a library or framework that provides such features.