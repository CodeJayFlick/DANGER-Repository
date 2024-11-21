Here is the translation of the given Java code into equivalent Python:

```Python
class ArtImageSection:
    def __init__(self, reader):
        try:
            self.offset = int.from_bytes(reader.read(4), 'little')
            self.size = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            raise IOException(str(e))

    @property
    def offset(self):
        return self.offset

    @property
    def size(self):
        return self.size

    @property
    def end(self):
        return self.offset + self.size


def to_data_type(self) -> dict:
    try:
        data_type = {'category_path': ['/art']}
        return data_type
    except Exception as e:
        raise DuplicateNameException(str(e))
```

Please note that Python does not have direct equivalent of Java's `StructConverter` and `DataType`. I've replaced them with a simple dictionary in the above code. Also, error handling is different between Java and Python. In this translation, exceptions are raised explicitly instead of being caught as they were in the original Java code.