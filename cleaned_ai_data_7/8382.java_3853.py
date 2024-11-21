class ArrayStMsType:
    PDB_ID = 0x1003

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt", False)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractArrayMsType:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
