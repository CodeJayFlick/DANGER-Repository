Here is the translation of the given Java code into equivalent Python:

```Python
class OverloadedMethodStMsType:
    PDB_ID = 0x1407

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt")
        reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractOverloadedMethodMsType:
    pass
```

Note that Python does not have direct equivalent of Java's `abstract` and `throws` keywords. Also, the type hinting in Python is done using the `type` keyword or by placing a string literal inside single quotes (as shown above).