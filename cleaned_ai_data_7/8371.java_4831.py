class AbstractUnionMsType:
    """This class represents various flavors of C/CC++ Union type."""
    
    TYPE_STRING = "union"

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_type_string(self):
        return self.TYPE_STRING
