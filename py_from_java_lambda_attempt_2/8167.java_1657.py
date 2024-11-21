Here is the translation of the given Java code into Python:

```Python
class GlobalData32MsSymbol:
    PDB_ID = 0x110d

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_32(pdb, reader, False))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GDATA32"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class DataSymbolInternals:
    @staticmethod
    def parse_32(pdb: 'AbstractPdb', reader: 'PdbByteReader', is_debug_info: bool) -> None:
        # Implementation of this method would depend on the actual requirements.
        pass

```

Please note that Python does not have direct equivalent to Java's static imports, annotations or generic types. The above code uses type hints for better readability and compatibility with future versions of Python which may support these features.