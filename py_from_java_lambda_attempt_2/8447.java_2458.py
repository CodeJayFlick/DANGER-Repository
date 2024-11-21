Here is the translation of the given Java code into equivalent Python:

```Python
class MemberFunction16MsType:
    PDB_ID = 0x0009

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractMemberFunctionMsType:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalent of Java's package declaration. In the above code, I've omitted it as per your request to write only Python and no other language.