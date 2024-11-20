Here is the translation of the Java code into Python:

```Python
class BTreeNodeRecord:
    def __init__(self, reader, descriptor):
        self._offset = reader.tell()
        self.unknown0 = reader.read_int()
        self.fileID = reader.read_int()
        self.unknown2 = reader.read_int()

        self._typeLength = reader.read_short()

        self.type = read_type(reader)

        if descriptor.get_kind() == 1:
            pass
        elif descriptor.get_kind() == 2:
            pass
        else:
            self.unknown4 = reader.read_int()
            self.unknown5 = reader.read_int()
            self.record_length = reader.read_int()

        self._descriptor = descriptor

    def get_type(self):
        return self.type

    def get_record_length(self):
        return self.record_length

    def get_descriptor(self):
        return self._descriptor

    def get_unknown0(self):
        return self.unknown0

    def get_unknown2(self):
        return self.unknown2

    def get_unknown3(self):
        return self.unknown3

    def get_unknown4(self):
        return self.unknown4

    def get_unknown5(self):
        return self.unknown5

    def get_fileID(self):
        return self.fileID

    def get_decmpfs_header(self):
        if self._descriptor.get_kind() == 1 and self.type == "DECMPFS_XATTR_NAME":
            return DecmpfsHeader(reader, self.record_length)
        else:
            pass
        # TODO: implement other cases for _decmpfs_header


def read_type(reader):
    buffer = ""
    for i in range(reader.read_short()):
        reader.seek(1)  # skip it...
        buffer += chr(reader.read_byte())
    return buffer

class DecmpfsHeader:
    def __init__(self, reader, record_length):
        pass
```

Please note that I did not implement the `DecmpfsHeader` class as you would need to define how this header is read from a file.