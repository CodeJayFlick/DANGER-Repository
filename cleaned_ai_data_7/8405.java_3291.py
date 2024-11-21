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
