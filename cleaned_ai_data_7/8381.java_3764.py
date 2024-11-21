class ArrayMsType:
    PDB_ID = 0x1503

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringNt", False)

    def get_pdb_id(self) -> int:
        return self.PDB_ID
