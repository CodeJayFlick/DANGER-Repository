class LocalProcedureStart3216MsSymbol:
    PDB_ID = 0x0204

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_3216(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROC32_16"
