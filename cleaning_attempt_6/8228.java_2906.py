class LocalProcedureStartIa64StMsSymbol:
    PDB_ID = 0x1015

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROCIA64_ST"

    def get_special_type_string(self) -> str:
        return "Type"
