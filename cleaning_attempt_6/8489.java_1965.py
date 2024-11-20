class Skip16MsType:
    PDB_ID = 0x0200

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader, 16)
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID


# Note: Python does not have direct equivalent of Java's abstract class and interface.
# We can use a regular class with some methods to achieve similar functionality.

class AbstractPdb:
    pass

class PdbByteReader:
    def skip_padding(self):
        pass
