Here is the translation of the given Java code into equivalent Python:

```Python
class VirtualFunctionTablePath16MsType:
    PDB_ID = 0x0012

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractVirtualFunctionTablePathMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `public`, and other access modifiers. Also, the type hinting is used to indicate the expected types for function parameters and return values.