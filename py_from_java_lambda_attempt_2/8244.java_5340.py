Here is the translation of the Java code into Python:

```Python
class ManagedLocalOrParameterSIMRMsSymbol:
    PDB_ID = 0x1121

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 8, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANMANYREG"
```

Note that I used Python's type hinting feature to indicate the types of parameters and variables.