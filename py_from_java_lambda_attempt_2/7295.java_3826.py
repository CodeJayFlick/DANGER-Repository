Here is the equivalent Python code:

```Python
class Ext4JournalHeaderS:
    def __init__(self, provider):
        self.h_magic = None
        self.h_blocktype = None
        self.h_sequence = None
        
        if isinstance(provider, bytes):
            reader = BinaryReader(provider)
        else:
            raise ValueError("Invalid provider type")
        
        # Journal is big-endian... opposite of the rest of the file.
        reader.set_endian('big')
        
        self.h_magic = int.from_bytes(reader.read(4), 'big')
        self.h_blocktype = int.from_bytes(reader.read(4), 'big')
        self.h_sequence = int.from_bytes(reader.reader, 'big')

    @property
    def h_magic(self):
        return self.h_magic

    @h_magic.setter
    def h_magic(self, value):
        self.h_magic = value

    @property
    def h_blocktype(self):
        return self.h_blocktype

    @h_blocktype.setter
    def h_blocktype(self, value):
        self.h_blocktype = value

    @property
    def h_sequence(self):
        return self.h_sequence

    @h_sequence.setter
    def h_sequence(self, value):
        self.h_sequence = value

class BinaryReader:
    def __init__(self, provider):
        if isinstance(provider, bytes):
            self.provider = provider
        else:
            raise ValueError("Invalid provider type")

    def read(self, size):
        return self.provider[:size]

    def set_endian(self, endian):
        pass  # No support for setting endianness in Python

class StructureDataType:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset
        self.fields = []

    def add(self, field_type, field_name, default_value=None):
        self.fields.append((field_type, field_name, default_value))

    @property
    def fields(self):
        return self.fields

# Example usage:
header = Ext4JournalHeaderS(b'\x00\x01\x02\x03\x04\x05\x06\x07')
print(header.h_magic)
```

Note that Python does not have direct support for big-endian or little-endian byte order, so the `set_endian` method in the `BinaryReader` class is a no-op. Also, I did not implement the `toDataType` method as it seems to be specific to Ghidra's data model and may require additional information about how you want to represent this structure in Python.