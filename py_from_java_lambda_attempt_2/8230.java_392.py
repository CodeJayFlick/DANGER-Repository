Here is the translation of the given Java code into equivalent Python:

```Python
class LocalProcedureStartMipsMsSymbol:
    PDB_ID = 0x1114

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartMipsSymbolInternals.parse(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROCMIPSSYM"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definition (`-> None`) which are used to indicate the expected types of a function's arguments and return value.