Here is the translation of the Java code into equivalent Python:

```Python
class LocalProcedureMipsIdMsSymbol:
    PDB_ID = 0x1148

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartMipsSymbolInternals.parse(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROCMIPSSYM_ID"

    def get_special_type_string(self) -> str:
        return "ID"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of the class, methods and variables is determined by their position in the file (top-level classes and functions are considered public).