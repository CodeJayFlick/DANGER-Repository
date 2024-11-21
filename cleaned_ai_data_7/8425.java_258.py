class FieldList16MsType:
    PDB_ID = 0x0204

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractFieldListMsType:
    pass


class PdbException(Exception):
    pass


class CancelledException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    pass
