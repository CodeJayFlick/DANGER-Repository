class LocalProcedure32IdMsSymbol:
    PDB_ID = 0x1146

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROC32_ID"

    def get_special_type_string(self) -> str:
        return "ID"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ProcedureStartSymbolInternals:
    @staticmethod
    def parse_32(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # implement this method as needed
        return None

