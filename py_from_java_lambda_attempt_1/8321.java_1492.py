Here is the translation of the given Java code into equivalent Python:

```Python
class With32MsSymbol:
    PDB_ID = 0x1104

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "WITH32"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of the class, methods and variables is determined by their position in the file (i.e., everything defined at module level are considered public).