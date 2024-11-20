class ManyRegisterVariableStMsSymbol:
    PDB_ID = 0x1005

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANYREG_ST"
