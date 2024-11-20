class AttributedLocalOrParameterSIRMsSymbol:
    PDB_ID = 0x112f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "ATTR_REGISTER"
