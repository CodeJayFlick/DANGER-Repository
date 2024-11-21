Here is the translation of the given Java code into Python:

```Python
class FriendClassMsType:
    PDB_ID = 0x140a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        reader.read(2)  # Padding. Read and discard 2 bytes.
        self.friend_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

class AbstractPdb:
    pass

class PdbByteReader:
    def read(self, n):
        raise NotImplementedError("read method not implemented")

    def parse_bytes(self, n):
        raise NotImplementedError("parse_bytes method not implemented")

    def align4(self):
        raise NotImplementedError("align4 method not implemented")


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        raise NotImplementedError("parse method not implemented")
```

Please note that the above Python code is a direct translation of the given Java code. It does not include any error handling or exception management as it was done in the original Java code.