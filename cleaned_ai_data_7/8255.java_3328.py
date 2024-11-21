class ManyRegisterVariable2MsSymbol:
    PDB_ID = 0x1117

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8Nt")

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "MANYREG2"

class AbstractPdb:
    pass

class PdbByteReader:
    pass
