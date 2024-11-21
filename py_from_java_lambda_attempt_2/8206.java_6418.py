Here is the translation of the given Java code into equivalent Python:

```Python
class LocalData32MsSymbol:
    PDB_ID = 0x110c

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_32(pdb, reader, False))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LDATA32"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class DataSymbolInternals:
    @staticmethod
    def parse_32(pdb: 'AbstractPdb', reader: 'PdbByteReader', is_private: bool) -> int:
        # Your implementation here
        return 0
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default unless you use double underscore (`__`) to make it private.

Also, the translation assumes that there are classes `AbstractPdb`, `PdbByteReader`, and `DataSymbolInternals` in your code which were not provided here.