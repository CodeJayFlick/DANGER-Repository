Here is the translation of the Java code into Python:

```Python
class BasePointerRelative16MsSymbol:
    PDB_ID = 0x0100

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, 16, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "BPREL16"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the type hints are used in this translation to indicate what types of arguments a function expects or returns. This is optional but can be useful for static analysis tools like mypy.