class LocalThreadStorage32StMsSymbol:
    PDB_ID = 0x100e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32_st(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LTHREAD32_ST"
