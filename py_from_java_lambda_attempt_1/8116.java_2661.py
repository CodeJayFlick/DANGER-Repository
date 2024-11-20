Here is the translation of the given Java code into equivalent Python:

```Python
class AttributedLocalOrParameterSIRMsSymbol:
    PDB_ID = 0x112f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "ATTR_REGISTER"
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also, the type hints are used in this translation to indicate what types each parameter should be (e.g., 'AbstractPdb' for pdb).