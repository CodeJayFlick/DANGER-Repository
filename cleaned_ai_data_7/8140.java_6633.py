class CvReservedMsSymbol:
    PDB_ID = 0x0008

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)
        self.record_length = reader.get_limit() - reader.get_index()

    def get_pdb_id(self):
        return PDB_ID

    def emit(self, builder: str) -> None:
        builder += f"{self.symbol_type_name()}, Length = 0x{self.record_length:x}"

    def symbol_type_name(self) -> str:
        return "CVRESERVE"

class AbstractPdb:
    pass

class PdbByteReader:
    def get_limit(self):
        raise NotImplementedError()

    def get_index(self):
        raise NotImplementedError()
