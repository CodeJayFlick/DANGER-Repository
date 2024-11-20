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
