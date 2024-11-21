class FriendFunctionMsType:
    PDB_ID = 0x150c

    def __init__(self, pdb: 'AbstractPdb', reader):
        super().__init__(pdb, reader)
        reader.read(2)  # padding
        self.friend_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        self.name = reader.read_string(pdb, StringParseType.STRING_NT)

    def get_pdb_id(self):
        return self.PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def read_bytes(self, bytes: int) -> None:
        raise NotImplementedError()

    def parse_string(self, pdb: 'AbstractPdb', string_parse_type: str) -> str:
        raise NotImplementedError()

    def read(self, bytes: int) -> None:
        raise NotImplementedError()
