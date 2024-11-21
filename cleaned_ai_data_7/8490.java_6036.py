class SkipMsType:
    PDB_ID = 0x1200

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32)
        self.reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractSkipMsType:
    pass


class PdbException(Exception):
    pass


class AbstractPdb:
    pass


class PdbByteReader:
    def align4(self) -> None:
        pass
