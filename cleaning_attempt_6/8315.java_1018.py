class UsingNamespaceMsSymbol:
    PDB_ID = 0x1124

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def emit(self, builder: str) -> None:
        builder += f"{self.get_symbol_type_name()}: {self.name}"

    def get_symbol_type_name(self) -> str:
        return "UNAMESPACE"


class AbstractPdb:
    pass


class PdbByteReader:
    pass
