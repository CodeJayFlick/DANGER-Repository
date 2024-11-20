Here is the translation of the given Java code into equivalent Python:

```Python
class Array16MsType:
    PDB_ID = 0x0003

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt", False)

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. It uses the underscore prefix to indicate internal use only (like `_Array16MsType__init`). Also, it doesn't support checked exceptions like Java does with `throws PdbException`.