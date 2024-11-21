class LocalSlotIndexFieldedLILMsSymbol:
    PDB_ID = 0x111a

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LOCALSLOT"

class AbstractLocalSlotIndexFieldedLILMsSymbol:
    pass
