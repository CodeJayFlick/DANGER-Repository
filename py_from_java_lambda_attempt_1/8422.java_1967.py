Here is the translation of the given Java code into equivalent Python:

```Python
class EnumerateStMsType:
    PDB_ID = 0x0403

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractEnumerateMsType:
    pass

class PdbException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` or `static`. Also, the concept of interfaces is different in Python. The given code assumes that you are using type hints for static analysis and IDEs like PyCharm which support this feature.