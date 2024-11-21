Here is the translation of the given Java code into Python:

```Python
class VersionTag:
    def __init__(self, reader):
        self._length = reader.read_int()
        self._version_string = reader.read_bytes(self._length)

    @property
    def length(self):
        return self._length

    @property
    def version_string(self):
        return self._version_string.decode('utf-8')

class BinaryReader:
    def read_int(self):
        # implementation of reading an integer from binary data
        pass

    def read_bytes(self, size):
        # implementation of reading a specified number of bytes from binary data
        pass


# Example usage:

reader = BinaryReader()  # replace with actual reader object
tag = VersionTag(reader)
print(tag.length)  # prints the length of the version string
print(tag.version_string)  # prints the contents of the version string

```

Please note that this is a simplified translation and does not include error handling or any specific implementation details. The `BinaryReader` class in Python would need to be implemented based on your actual binary data format, which was not provided in the original Java code.