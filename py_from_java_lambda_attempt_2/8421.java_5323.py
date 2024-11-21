Here is the translation of the given Java code into equivalent Python:

```Python
class EnumerateMsType:
    PDB_ID = 0x1502

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID


class AbstractEnumerateMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass

```

Please note that Python does not have direct equivalent of Java's package declaration, import statements or annotations. Also, the concept of abstract classes and interfaces is slightly different in Python compared to Java.