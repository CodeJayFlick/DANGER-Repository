Here is the equivalent Python code:

```Python
class PackedSwitchPayload:
    MAGIC = 0x0100

    def __init__(self, reader):
        self.ident = reader.read_short()
        self.size = reader.read_short()
        self.first_key = reader.read_int()
        self.targets = reader.read_array(self.size & 0xffff)

    @property
    def ident(self):
        return self._ident

    @property
    def size(self):
        return self._size

    @property
    def first_key(self):
        return self._first_key

    @property
    def targets(self):
        return self._targets


class DataType:
    pass


def to_data_type(self) -> DataType:
    structure = {"ident": "WORD", "size": "WORD", "first_key": "DWORD"}
    if self.size & 0xffff > 0:
        structure["targets"] = f"Array({self.size & 0xffff} x DWORD)"
    else:
        structure["targets"] = None
    return structure


# Usage example:

class BinaryReader:
    def read_short(self):
        pass

    def read_int(self):
        pass

    def read_array(self, size):
        pass


reader = BinaryReader()
payload = PackedSwitchPayload(reader)
print(payload.ident)  # prints the ident value
print(payload.size)   # prints the size value
print(payload.first_key)  # prints the first key value
for target in payload.targets:
    print(target)  # prints each target

# Create a data type from the payload
data_type = to_data_type(payload)
print(data_type)  # prints the data type as a dictionary
```

Please note that this is not an exact translation, but rather an equivalent Python code. The original Java code uses classes and methods specific to the Java programming language, which do not have direct equivalents in Python.