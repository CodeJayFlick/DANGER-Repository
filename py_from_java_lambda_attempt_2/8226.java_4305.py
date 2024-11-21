Here is the translation of the given Java code into equivalent Python:

```Python
class LocalProcedureStart32StMsSymbol:
    PDB_ID = 0x100a

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32st(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROC32_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definition (`-> None`) which are used to indicate the expected types of a function's arguments and return value. This feature was added in Python 3.5.