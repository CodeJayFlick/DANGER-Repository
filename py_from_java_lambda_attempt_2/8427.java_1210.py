Here is the translation of the given Java code into equivalent Python:

```Python
class FriendClass16MsType:
    PDB_ID = 0x040b

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.friend_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def skip_padding(self):
        pass

    @staticmethod
    def parse(pdb, reader, category, size):
        raise NotImplementedError("Not implemented")


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category, size):
        raise NotImplementedError("Not implemented")
```

Please note that this translation is not a direct conversion from Java to Python. The given code seems to be part of an API for parsing PDB files in Ghidra, and the provided classes are abstract or interfaces. Therefore, their implementation depends on specific requirements and might vary based on actual use cases.

In this example, I've kept the structure similar to the original Java code but with Python syntax. The `AbstractPdb`, `PdbByteReader`, and `RecordNumber` classes have been left as abstract base classes or interfaces since they don't seem to be fully implemented in the given code snippet.