# This class represents various flavors of C++ Class type.
class AbstractClassMsType(AbstractCompositeMsType):
    TYPE_STRING = "class"

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_type_string(self) -> str:
        return self.TYPE_STRING
