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
