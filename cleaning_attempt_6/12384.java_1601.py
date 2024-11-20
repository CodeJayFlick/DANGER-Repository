class SignedCharDataType:
    def __init__(self):
        self.data_type_manager = None

    @staticmethod
    def get_data_type():
        if not hasattr(SignedCharDataType, 'data_type'):
            SignedCharDataType.data_type = SignedCharDataType()
        return SignedCharDataType.data_type

    def clone(self):
        return SignedCharDataType()

    def __str__(self):
        return "Signed Character (ASCII)"

    def default_label_prefix(self):
        return "SCHAR"

    def c_declaration(self):
        return "signed char"

    def c_type_declaration(self, data_organization=None):
        if not data_organization:
            return self.c_declaration()
        else:
            return f"{self.name()} {self.c_declaration()}"
