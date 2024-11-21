class GlobalProcedureStartIa64StMsSymbol:
    PDB_ID = 0x1016

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROCIA64_ST"

    def get_special_type_string(self) -> str:
        return "Type"
