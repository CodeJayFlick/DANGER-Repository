class LocalSymbolInOptimizedCodeMsSymbol:
    PDB_ID = 0x113e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "LOCAL"

class AbstractLocalSymbolInOptimizedCodeMsSymbol:
    pass

class PdbByteReader:
    pass

class AbstractPdb:
    pass
