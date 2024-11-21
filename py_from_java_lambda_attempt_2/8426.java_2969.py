Here is the translation of the given Java code into equivalent Python:

```Python
class FieldListMsType:
    PDB_ID = 0x1203

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractFieldListMsType:
    pass
```

Note that Python does not have direct equivalent of Java's package declaration. Also, the `CancelledException` and `PdbException` are not directly translatable to Python as they are custom exceptions in Java which do not exist in Python by default.

In this translation:

- The class names remain same.
- The constructor is translated into an initializer method (`__init__`) with equivalent parameters.
- The getter method remains the same, just translated from `getPdbId()` to `get_pdb_id()`.
- A base class `AbstractFieldListMsType` was added as it seems like a superclass in Java.