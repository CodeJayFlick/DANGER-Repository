Here is the translation of the given Java code into equivalent Python:

```Python
class ArrayStMsType:
    PDB_ID = 0x1003

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt", False)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractArrayMsType:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalent of Java's package, import statement or public/private access modifiers. The translation is done in a way to maintain the same structure and functionality as the original code but it may look different due to these differences.