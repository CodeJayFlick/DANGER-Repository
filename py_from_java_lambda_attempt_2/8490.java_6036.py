Here is the translation of the given Java code into equivalent Python:

```Python
class SkipMsType:
    PDB_ID = 0x1200

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32)
        self.reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractSkipMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    def align4(self) -> None:
        pass
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. Also, the concept of interfaces is different in Python than it is in Java.