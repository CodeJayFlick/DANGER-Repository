Here is the translation of the given Java code into equivalent Python:

```Python
class ManLocOrParamReltoVFPStMsSymbol:
    PDB_ID = 0x1022

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "MANFRAMEREL_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the `@Override` annotation in Java has no direct equivalent in Python as it is used to indicate that a method is overriding one from its superclass.