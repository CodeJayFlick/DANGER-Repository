class Procedure16MsType:
    PDB_ID = 0x0008

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractProcedureMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass
