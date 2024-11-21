Here is the translation of the given Java code into equivalent Python:

```Python
class Cobol016MsType:
    PDB_ID = 0x000b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractCobol0MsType:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Please note that this is a direct translation of the Java code into Python, and it might not be perfect. The `AbstractPdb`, `PdbByteReader` classes are placeholders as their actual implementations were missing in the given Java code.