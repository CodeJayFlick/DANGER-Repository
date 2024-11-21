class SignedWordDataType:
    def __init__(self):
        self.description = "Signed Word (sdw, 2-bytes)"
        self.length = 2
        self.assembly_mnemonic = "sdw"

    def get_description(self):
        return self.description

    def get_length(self):
        return self.length

    def get_assembly_mnemonic(self):
        return self.assembly_mnemonic

    def get_opposite_signedness_data_type(self, data_type_manager=None):
        if not data_type_manager:
            data_type_manager = "default"
        return SignedWordDataType(data_type_manager)

    def clone(self, data_type_manager="default"):
        if data_type_manager == self.get_data_type_manager():
            return self
        else:
            return SignedWordDataType(data_type_manager)

    @staticmethod
    def get_c_type_declaration(data_organization):
        # This method is not fully implemented in the Java code.
        pass

SignedWordDataType.data_type = SignedWordDataType()
