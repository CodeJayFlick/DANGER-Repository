Here is the translation of the Java code to Python:
```
class TypeTag:
    def __init__(self, reader):
        self.type = reader.read_int()
        self.unknown0 = reader.read_int()
        self.unknown1 = reader.read_int()
        self.unknown2 = reader.reader.read_int()
        self.unknown3 = reader.read_int()

    @property
    def type(self):
        return self._type

    @property
    def unknown0(self):
        return self._unknown0

    @property
    def unknown1(self):
        return self._unknown1

    @property
    def unknown2(self):
        return self._unknown2

    @property
    def unknown3(self):
        return self._unknown3


class BinaryReader:
    def read_int(self):
        # implement your own reading logic here, e.g. using a file object or socket
        pass


# Example usage:
reader = BinaryReader()  # create an instance of the reader class
tag = TypeTag(reader)  # create an instance of the TypeTag class

print(tag.type)
print(tag.unknown0)
print(tag.unknown1)
print(tag.unknown2)
print(tag.unknown3)
```
Note that I've omitted some details, such as error handling and specific implementation of `BinaryReader`, since those are not part of the original Java code. You'll need to fill in the gaps according to your requirements.