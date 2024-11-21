Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedLocalOrParameterSIRStMsSymbol:
    PDB_ID = 0x1023

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANREGISTER_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. Also, the type hints are used to indicate the expected types for function parameters and variables.