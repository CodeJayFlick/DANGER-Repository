class OverloadedMethodStMsType:
    PDB_ID = 0x1407

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt")
        reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractOverloadedMethodMsType:
    pass
