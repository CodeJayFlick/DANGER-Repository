class GlobalProcedureIa64IdMsSymbol:
    PDB_ID = 0x114b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROCIA64_ID"

    def get_special_type_string(self) -> str:
        return "ID"
