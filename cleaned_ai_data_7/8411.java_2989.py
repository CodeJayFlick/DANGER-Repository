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
