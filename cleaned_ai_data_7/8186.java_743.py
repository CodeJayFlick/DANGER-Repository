class GlobalProcedureStartMipsMsSymbol:
    PDB_ID = 0x1115

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartMipsSymbolInternals.parse(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROCMIPSSYM"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ProcedureStartMipsSymbolInternals:
    @staticmethod
    def parse(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # implementation of parsing logic here
        return None

