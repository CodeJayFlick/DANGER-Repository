class GlobalThreadStorage32MsSymbol:
    PDB_ID = 0x1113

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GTHREAD32"
