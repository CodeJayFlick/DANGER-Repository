Here is the translation of the given Java code into Python:

```Python
class DataReferenceStMsSymbol:
    PDB_ID = 0x0401

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ReferenceSymbolInternals.parse_st(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "DATAREF_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the type hints are used in this code to indicate what types of arguments a function expects or what type it returns. This is for documentation purposes only; Python itself doesn't enforce these constraints at runtime.