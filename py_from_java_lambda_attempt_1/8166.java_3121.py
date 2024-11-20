Here is the translation of the given Java code into Python:

```Python
class GlobalData3216MsSymbol:
    PDB_ID = 0x0202

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_3216(pdb, reader, False))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GDATA32_16"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class DataSymbolInternals:
    @staticmethod
    def parse_3216(pdb: 'AbstractPdb', reader: 'PdbByteReader', is_private: bool) -> None:
        # Your code here...
        return None

```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of class members in Python can be controlled by using double underscore (`__`) or single underscore (`_`).