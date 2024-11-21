Here is the translation of the given Java code into equivalent Python:

```Python
class LocalSymbolInOptimizedCode2005MsSymbol:
    PDB_ID = 0x1133

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")  # might need St version here
        pass

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LOCAL_2005"
```

Note that Python does not have direct equivalent of Java's package declaration, import statements or public/private access modifiers. The class and its methods are defined directly in the script.