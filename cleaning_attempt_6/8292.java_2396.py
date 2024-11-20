class Reserved2MsSymbol:
    PDB_ID = 0x101d

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder: str) -> None:
        builder += self.get_symbol_type_name()

    def get_symbol_type_name(self) -> str:
        return "RESERVED2"
