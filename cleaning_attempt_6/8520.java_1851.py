class VirtualFunctionTablePointerWithOffsetMsType:
    PDB_ID = 0x140c

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, 2)

    def get_pdb_id(self) -> int:
        return self.PDB_ID
