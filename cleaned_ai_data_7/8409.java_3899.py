class DimensionedArrayConstBoundsUpper16MsType:
    PDB_ID = 0x0208

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def get_pdb_id(self):
        return self.PDB_ID


def parse_beginning_fields(reader):
    rank = reader.read_unsigned_short()
    type_record_number = RecordNumber.parse(pdb=reader.pdb, reader=reader, category='TYPE', size=16)


class AbstractPdb:
    pass


class PdbByteReader:
    def read_unsigned_short(self):
        # implementation
        pass

    @property
    def pdb(self):
        return self._pdb

    def parse_unsigned_short_val(self):
        # implementation
        pass

    def parse_record_number(self, category='TYPE', size=16):
        # implementation
        pass


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category='TYPE', size=16):
        # implementation
        pass
