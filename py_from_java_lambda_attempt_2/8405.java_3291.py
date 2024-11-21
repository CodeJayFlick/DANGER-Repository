Here is the translation of the given Java code into Python:

```Python
class DerivedClassListMsType:
    PDB_ID = 0x1204

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    pass
```

Note that Python does not have direct equivalents for Java's `public`, `static`, and `throws` keywords. Also, the type hinting is done using the `type: 'AbstractPdb'` syntax which indicates that a variable should be of type `'AbstractPdb'`.