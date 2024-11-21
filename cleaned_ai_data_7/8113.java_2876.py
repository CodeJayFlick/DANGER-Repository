class AttribLocOrParamReltoAMPMsSymbol:
    PDB_ID = 0x1130

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "ATTR_REGREL"
