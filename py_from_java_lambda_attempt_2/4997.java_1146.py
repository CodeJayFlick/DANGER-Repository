Here is the translation of the Java code into Python:

```Python
class CliStreamGuid:
    def __init__(self, header, offset, rva, reader):
        self.header = header
        self.offset = offset
        self.rva = rva
        self.reader = reader
        self.num_guids = self.header.get_size() // 16

    @staticmethod
    def get_name():
        return "#GUID"

    def parse(self):
        return True

    def get_guid(self, index):
        if index < 0 or index >= self.num_guids * 16:
            return None
        try:
            self.reader.set_pointer_index(self.offset + index)
            guid = GUID()
            guid.from_reader(self.reader)
            return guid
        except Exception as e:
            return None

    def to_data_type(self):
        struct = StructureDataType(CategoryPath(PATH), self.header.get_name(), 0)
        for i in range(self.num_guids):
            guid_dt = GuidDataType()
            struct.add(guid_dt, "[" + hex(i) + "]", None)
        return struct


class GUID:
    def __init__(self):
        pass

    @classmethod
    def from_reader(cls, reader):
        # This method should be implemented based on the actual format of the GUID in the stream.
        pass
```

Note that I've made some assumptions about how to translate certain parts of the code. For example, `GUID` is a class that seems to represent a 128-bit Globally Unique Identifier (GUID). In Python, we can create such a class with an initializer and a method for reading from a reader object.

The rest of the translation follows standard conventions in Python programming.