class OneMethodStMsType:
    PDB_ID = 0x140b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractOneMethodMsType:
    pass

class PdbException(Exception):
    pass
