class SignedLeb128DataType:
    def __init__(self):
        self.name = "sleb128"
        self.description = "Signed Dwarf LEB128-Encoded Number"

    @staticmethod
    def get_data_type():
        return SignedLeb128DataType()

    def clone(self, dtm=None):
        if dtm is None:
            dtm = self.get_datatype_manager()
        return type("SignedLeb128DataType", (SignedLeb128DataType,), {})(dtm)

    def get_mnemonic(self, settings):
        return self.name

    def get_default_label_prefix(self):
        return "sleb128"


class DataTypeManager:
    pass


def main():
    dt = SignedLeb128DataType.get_data_type()
    print(dt.description)


if __name__ == "__main__":
    main()

