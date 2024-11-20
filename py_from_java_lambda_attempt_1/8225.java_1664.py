Here is the translation of the given Java code into equivalent Python:

```Python
class LocalProcedureStart32MsSymbol:
    PDB_ID = 0x110f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROC32"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function signature (`-> None`) which are optional but can be useful for static analysis tools or IDEs to provide better code completion and error checking.