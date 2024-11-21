Here is the translation of the given Java code into Python:

```Python
class BasicArray16MsType:
    PDB_ID = 0x000d

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractBasicArrayMsType:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Please note that this is a direct translation of the Java code into Python. The equivalent classes and methods in Python are different from those in Java, but they serve the same purpose.