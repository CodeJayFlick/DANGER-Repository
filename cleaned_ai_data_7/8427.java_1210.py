class FriendClass16MsType:
    PDB_ID = 0x040b

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.friend_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def skip_padding(self):
        pass

    @staticmethod
    def parse(pdb, reader, category, size):
        raise NotImplementedError("Not implemented")


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category, size):
        raise NotImplementedError("Not implemented")
