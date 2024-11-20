Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalProcedureStart32StMsSymbol:
    PDB_ID = 0x100b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32_st(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROC32_ST"

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class ProcedureStartSymbolInternals:
    @staticmethod
    def parse_32_st(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # This method is not implemented in the given Java code, so it's left as a placeholder.
        pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default unless you explicitly use double underscore (`__`) to make them private.

Also note that the `@Override` annotation in Java has no direct equivalent in Python as it only serves as a hint for IDEs or code analysis tools about which method is being overridden.