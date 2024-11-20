Here is the translation of the given Java code into equivalent Python:

```Python
class ManLocOrParamReltoAMPMsSymbol:
    PDB_ID = 0x1122

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "MANREGREL"
```

Note that Python does not have direct equivalent of Java's package declaration. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass or interface; this concept doesn't exist in Python as it has no explicit override mechanism.

In addition, I've replaced the constructor with an initializer (`__init__`) and added type hints for clarity.