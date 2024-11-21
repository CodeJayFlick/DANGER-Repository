Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalProcedureStart3216MsSymbol:
    PDB_ID = 0x0205

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_3216(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROC32_16"
```

Note that Python does not have direct equivalent of Java's package declaration. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; this concept doesn't exist directly in Python.

In addition, Python has no direct equivalent for Java's static final variable.