Here is the translation of the given Java code into equivalent Python:

```Python
class MemberModifyMsType:
    PDB_ID = 0x1513

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractMemberModifyMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalent of Java's package, import statements or annotations. The `AbstractPdb`, `PdbByteReader` and other classes are just placeholders as they were in the original code.