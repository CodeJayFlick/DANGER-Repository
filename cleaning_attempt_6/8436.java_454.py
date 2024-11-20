class IndexMsType:
    PDB_ID = 0x1404

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        reader.read(2)  # Throw away 2 bytes.
        self.referenced_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    @property
    def get_pdb_id(self):
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def parse_bytes(self, num_bytes):
        # Implementation of this method is left out as it's not provided in the given Java code.
        pass

    def read(self, num_bytes):
        # Implementation of this method is left out as it's not provided in the given Java code.
        pass


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, record_category, size):
        # Implementation of this method is left out as it's not provided in the given Java code.
        pass

