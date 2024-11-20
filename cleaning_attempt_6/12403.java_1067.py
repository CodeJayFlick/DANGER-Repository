class TerminatedUnicode32DataType:
    data_type = None  # class variable

    def __init__(self):
        self.__init__None()

    def __init__None(self):
        if not isinstance(TerminatedUnicode32DataType.data_type, type):
            TerminatedUnicode32DataType.data_type = type("TerminatedUnicode32", (object,), {
                "__doc__": """A null-terminated UTF-32 string data type.""",
                "name": "Terminated Unicode 32",
                "mnemonic": "unicode32",
                "default_label": "UNICODE",
                "label_prefix": "UNI",
                "abbrev_label_prefix": "u",
                "description": "String (Null Terminated UTF-32 Unicode)",
                "charset": "UTF-32",
                "replacement_data_type": WideChar32DataType.data_type,
                "string_layout_enum": StringLayoutEnum.NULL_TERMINATED_UNBOUNDED
            })

    def clone(self, dtm):
        if dTM == self.get_data_type_manager():
            return self
        else:
            return TerminatedUnicode32DataType(dtm)

class WideChar32DataType:
    data_type = None  # class variable

class StringLayoutEnum:
    NULL_TERMINATED_UNBOUNDED = "Null Terminated Unbounded"

class CharsetInfo:
    UTF32 = "UTF-32"
