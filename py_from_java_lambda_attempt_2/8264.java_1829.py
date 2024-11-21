Here is the translation of the given Java code into Python:

```Python
class ObjectNameStMsSymbol:
    PDB_ID = 0x0009

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "OBJNAME_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of a class or method in Python is determined by its position within the file (top-level functions are public, while nested classes and methods are private).