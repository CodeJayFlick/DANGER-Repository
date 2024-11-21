class WordDataType:
    def __init__(self):
        self.description = "Unsigned Word (dw, 2-bytes)"
        self.length = 2
        self.assembly_mnemonic = "dw"

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Length must be a non-negative integer")
        self._length = value

    @property
    def assembly_mnemonic(self):
        return self._assembly_mnemonic

    @assembly_mnemonic.setter
    def assembly_mnemonic(self, value):
        if not isinstance(value, str) or len(value) > 10:
            raise ValueError("Assembly mnemonic must be a string with at most 10 characters")
        self._assembly_mnemonic = value

def get_opposite_signedness_data_type():
    return SignedWordDataType()

class SignedWordDataType(WordDataType):
    def __init__(self, dtm=None):
        super().__init__()
        if dtm is None:
            dtm = DataTypeManager()
        self.dtm = dtm
