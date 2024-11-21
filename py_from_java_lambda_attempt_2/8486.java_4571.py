Here is the translation of the given Java code into Python:

```Python
class Procedure16MsType:
    PDB_ID = 0x0008

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractProcedureMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalent of Java's package, import statement or the concept of static variables. Also, in Python, we don't need to specify types for method parameters and return values like we do in Java.