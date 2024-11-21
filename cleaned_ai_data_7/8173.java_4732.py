class GlobalManagedDataStMsSymbol:
    PDB_ID = 0x1021

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_32_st(pdb, reader, True))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GMANDATA32_ST"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class DataSymbolInternals:
    @staticmethod
    def parse_32_st(pdb: 'AbstractPdb', reader: 'PdbByteReader', is_managed_data: bool) -> None:
        # This method should be implemented according to the requirements of your program.
        pass

