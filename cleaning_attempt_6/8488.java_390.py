class ReferencedSymbolMsType:
    PDB_ID = 0x020c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        record_length = reader.read_uint16()
        record_reader = reader.get_sub_reader(record_length)
        self.symbol_record = pdb.get_symbol_parser().parse(record_reader)

    @property
    def pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        # No documented "good" API for output.
        self.symbol_record.emit(builder)


class AbstractMsType:
    pass


class PdbByteReader:
    def read_uint16(self):
        raise NotImplementedError()

    def get_sub_reader(self, length):
        raise NotImplementedError()


class AbstractPdb:
    def get_symbol_parser(self):
        raise NotImplementedError()
