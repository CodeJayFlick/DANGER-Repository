class DimensionedArrayConstBoundsUpperMsType:
    PDB_ID = 0x1207

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def get_pdb_id(self):
        return self.PDB_ID


def parse_beginning_fields(reader):
    type_record_number = RecordNumber.parse(pdb=reader.pdb, reader=reader)
    rank = reader.read_unsigned_short()


class AbstractPdb:
    pass

class PdbByteReader:
    @property
    def pdb(self):
        raise NotImplementedError("This method should be implemented in the subclass")

    def parse_unsigned_short_val(self):
        raise NotImplementedError("This method should be implemented in the subclass")


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, record_category, size):
        raise NotImplementedError("This method should be implemented in the subclass")
