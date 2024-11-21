Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalThreadStorage32StMsSymbol:
    PDB_ID = 0x100f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32_st(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GTHREAD32_ST"

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class ThreadStorageSymbolInternals:
    @staticmethod
    def parse_32_st(reader: 'PdbByteReader', pdb: 'AbstractPdb') -> None:
        # implementation of this method is missing in the original Java code, so it's left as a placeholder here.
        pass
```

Please note that Python does not have direct equivalent to Java concepts like `package`, `public class`, etc. Also, Python does not require explicit declaration of types for variables and function parameters (like `int` or `str`). The above translation is based on the assumption that you want a straightforward conversion from Java to Python without changing the original logic.