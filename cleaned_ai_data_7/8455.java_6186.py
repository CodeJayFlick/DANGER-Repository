class MethodListMsType:
    PDB_ID = 0x1206

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def parse_one_record(self, pdb_in: 'AbstractPdb', reader: 'PdbByteReader') -> 'MethodRecordMs':
        return MethodRecordMs(pdb_in, reader)


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class MethodRecordMs:
    def __init__(self, pdb_in: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        self.pdb_in = pdb_in
        self.reader = reader

