class DimensionedArrayVarBoundsLowerUpper16MsType:
    PDB_ID = 0x020b

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self):
        return self.PDB_ID


# Note: Python does not have direct equivalent of Java's "throws" keyword.
