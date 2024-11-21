Here is the translation of the given Java code into equivalent Python:

```Python
class ParameterSlotIndexFieldedLILMsSymbol:
    PDB_ID = 0x111b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "PARAMSLOT"


class AbstractParameterSlotIndexFieldedLILMsSymbol:
    pass


class PdbByteReader:
    pass


class AbstractPdb:
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `public` and `throws`. Also, the concept of static variables is different in both languages. In this translation, I've used a class variable (`PDB_ID`) instead of a static final int field.

The `@Override` annotation is also specific to Java and does not have an equivalent in Python.