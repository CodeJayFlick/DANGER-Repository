class QWordDataType:
    def __init__(self):
        self.description = "Unsigned Quad-Word (dq, 8-bytes)"
        self.length = 8
        self.assembly_mnemonic = "dq"

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
        self._length = value

    @property
    def assembly_mnemonic(self):
        return self._assembly_mnemonic

    @assembly_mnemonic.setter
    def assembly_mnemonic(self, value):
        self._assembly_mnemonic = value

    def get_opposite_signedness_data_type(self):
        return SignedQWordDataType()

    def clone(self):
        return QWordDataType()
