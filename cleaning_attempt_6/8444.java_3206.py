class ManagedStMsType:
    PDB_ID = 0x140f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID
