Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedMsType:
    PDB_ID = 0x1514

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID


class AbstractManagedMsType:
    pass  # This class is not implemented in the given Java code.