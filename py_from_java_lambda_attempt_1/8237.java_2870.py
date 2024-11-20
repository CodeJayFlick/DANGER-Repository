Here is the translation of the given Java code into equivalent Python:

```Python
class LocalThreadStorage32MsSymbol:
    PDB_ID = 0x1112

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32(reader, pdb))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LTHREAD32"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ThreadStorageSymbolInternals:
    @staticmethod
    def parse_32(reader: 'PdbByteReader', pdb: 'AbstractPdb') -> None:
        # implement this method as needed
        return None

```

Please note that Python does not have direct equivalent of Java's `package`, `public`, and other access modifiers. Also, the type hints are used to indicate the expected types of function parameters and variables.