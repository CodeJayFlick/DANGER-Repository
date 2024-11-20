class Public32StMsSymbol:
    PDB_ID = 0x1009

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, self.parse_32_st(pdb, reader))

    @classmethod
    def parse_32_st(cls, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> int:
        # implement this method as needed
        pass

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "PUBSYM32_ST"


class AbstractPdb:
    pass


class PdbByteReader:
    pass
