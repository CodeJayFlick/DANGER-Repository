Here is the translation of the given Java code into equivalent Python:

```Python
class DimensionedArrayMsType:
    PDB_ID = 0x1508

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringNt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractDimensionedArrayMsType:
    pass

class PdbException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that in the constructor (`__init__`) method, I used type hints for clarity but it doesn't affect the functionality as Python 3.x does not enforce these types at runtime.