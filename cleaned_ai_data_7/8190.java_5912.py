class GlobalThreadStorage32StMsSymbol:
    PDB_ID = 0x100f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32_st(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GTHREAD32_ST"

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class ThreadStorageSymbolInternals:
    @staticmethod
    def parse_32_st(reader: 'PdbByteReader', pdb: 'AbstractPdb') -> None:
        # implementation of this method is missing in the original Java code, so it's left as a placeholder here.
        pass
