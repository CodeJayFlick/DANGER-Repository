class Public16MsSymbol:
    PDB_ID = 0x0103

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, DataSymbolInternals.parse_16(pdb, reader, False))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "PUBSYM16"


class AbstractPublic16Or3216MsSymbol:
    pass


class DataSymbolInternals:
    @staticmethod
    def parse_16(pdb: 'AbstractPdb', reader: 'PdbByteReader', is_private: bool) -> None:
        # Your code here to handle parsing 16 Ms symbol.
        pass


from abc import ABC, abstractmethod

class AbstractPdb(ABC):
    @abstractmethod
    def get_pdb(self) -> str:
        pass


class PdbByteReader:
    pass
