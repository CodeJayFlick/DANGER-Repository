class OneMethod16MsType:
    PDB_ID = 0x040c

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID
