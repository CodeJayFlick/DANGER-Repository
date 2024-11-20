class GlobalProcedureStart32StMsSymbol:
    PDB_ID = 0x100b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32_st(pdb, reader))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROC32_ST"

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class ProcedureStartSymbolInternals:
    @staticmethod
    def parse_32_st(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # This method is not implemented in the given Java code, so it's left as a placeholder.
        pass
