class Public32MsSymbol:
    PDB_ID = 0x110e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, self.parse_symbol(pdb, reader))

    @classmethod
    def parse_symbol(cls, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> int:
        # This method is not implemented in the original Java code.
        pass

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "PUBSYM32"


class AbstractPublic32MsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', symbol: int) -> None:
        pass


# Note that the following classes are not implemented in this translation.
class PdbByteReader:
    pass

class AbstractPdb:
    pass
