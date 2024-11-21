class DimensionedArrayConstBoundsLowerUpper16MsType:
    PDB_ID = 0x0209

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def get_pdb_id(self):
        return self.PDB_ID


def parse_beginning_fields(self, reader):
    try:
        self.rank = reader.read_uint16()
        type_record_number = RecordNumber.parse(pdb=reader.pdb, reader=reader, category='TYPE', size=16)
        self.type_record_number = type_record_number
    except Exception as e:
        raise PdbException('Not enough data left to parse') from e


class AbstractPdb:
    pass

class PdbByteReader:
    def read_uint16(self):
        # implement your logic here for reading uint16 value
        return 0

class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category='TYPE', size=4):
        # implement your logic here to parse the record number
        pass


class PdbException(Exception):
    pass
