Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedLocalOrParameterSIMR2MsSymbol:
    PDB_ID = 0x1123

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANMANYREG2"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that in the constructor (`__init__`) method, we are using type hints for parameters and return types as per PEP 484 (Type Hints).