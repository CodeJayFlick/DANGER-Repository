class UserDefinedType16MsSymbol:
    PDB_ID = 0x0004

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, self._parse_symbol(pdb, reader))

    @staticmethod
    def _parse_symbol(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> str:
        return UserDefinedTypeSymbolInternals.parse(pdb, reader, 16, StringParseType.StringUtf8St)

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "UDT_16"
