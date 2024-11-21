Here is the translation of the given Java code into equivalent Python:

```Python
class LocalData32StMsSymbol:
    PDB_ID = 0x1007

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_32_st(pdb, reader, False))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LDATA32_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definitions (`-> None`) which are optional but recommended for better code readability and maintainability.