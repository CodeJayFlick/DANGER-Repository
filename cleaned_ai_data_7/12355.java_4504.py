class PascalString255DataType:
    def __init__(self):
        self.data_type_name = "PascalString255"
        self.mnemonic = "p_string255"
        self.default_label = "PASCAL255"
        self.label_prefix = "P_STR"
        self.abbrev_label_prefix = "p"
        self.description = "String (Pascal 255)"
        self.charset = None
        self.replacement_data_type = ByteDataType()
        self.string_layout_enum = StringLayoutEnum.PASCAL_255

    def copy(self, retain_identity=False):
        return PascalString255DataType()

class ByteDataType:
    pass

class StringLayoutEnum:
    PASCAL_255 = "Pascal 255"

# Create an instance of the data type
pascal_string_data_type = PascalString255DataType()
