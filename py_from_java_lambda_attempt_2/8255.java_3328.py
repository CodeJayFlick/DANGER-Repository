Here is the translation of the given Java code into equivalent Python:

```Python
class ManyRegisterVariable2MsSymbol:
    PDB_ID = 0x1117

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8Nt")

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "MANYREG2"

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of a class or method in Python is determined by its position within the package structure, with top-level modules being considered as having public scope.

Also note that I used type hints for parameters and return types to make it clear what kind of data each parameter should be expecting.