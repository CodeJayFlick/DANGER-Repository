class FieldListMsType:
    PDB_ID = 0x1203

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractFieldListMsType:
    pass
