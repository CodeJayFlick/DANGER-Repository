Here is the translation of the Java code to Python:
```
class RelocationImportedName:
    def __init__(self, reader):
        self.index = reader.read_next_short()
        self.offset = reader.read_next_short()

    @property
    def index(self):
        return self._index

    @property
    def offset(self):
        return self._offset


def read_next_short(reader):
    # assume this function reads a short integer from the input stream
    pass  # implement me!
```
Note that I've replaced the `BinaryReader` class with a hypothetical `reader` object, which is assumed to have a method called `read_next_short()` that returns a short integer. You would need to implement this method based on your specific use case.

Also, in Python, we don't need explicit getters and setters like Java does; instead, we can define properties using the `@property` decorator. This allows us to access the underlying attributes as if they were public variables.