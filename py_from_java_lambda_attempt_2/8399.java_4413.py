Here is the translation of the given Java code into equivalent Python:

```Python
class Cobol0MsType:
    PDB_ID = 0x100a

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractCobol0MsType:
    pass

class PdbException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` or `static`. In Python, everything is public unless you explicitly use double underscore (`__`) to make it private. Also, there are no checks for null values in the constructor as Python doesn't support null values directly like Java does with `null`.

Also note that I've used type hints where possible but these are not enforced by Python itself and only serve as documentation.