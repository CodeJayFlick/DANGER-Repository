class StringDataType:
    def __init__(self):
        self.data_type_name = "string"
        self.mnemonic = "ds"
        self.default_label = "STRING"
        self.label_prefix = "STR"
        self.abbrev_label_prefix = "s"
        self.description = "String (fixed length)"
        self.charset = USE_CHARSET_DEF_DEFAULT
        self.replacement_data_type = CharDataType.dataType
        self.string_layout_enum = StringLayoutEnum.FIXED_LEN

    def clone(self, dtm):
        if dtm == self.get_datatype_manager():
            return self
        else:
            return StringDataType(dtm)

class AbstractStringDataType:
    pass

USE_CHARSET_DEF_DEFAULT = None  # equivalent to Java's static final variable
CharDataType = None  # equivalent to Java's class reference
StringLayoutEnum = None  # equivalent to Java's enum reference

# Initialize the ClassTranslator (equivalent to Java's static block)
ClassTranslator.put("ghidra.app.plugin.data.MBCSDataType", StringDataType.__name__)
ClassTranslator.put("ghidra.app.plugin.core.data.mbc.MBCSDataType",
                    StringDataType.__name__)

StringDataType.data_type = StringDataType()

# equivalent to the constructor
def __init__(self, dtm=None):
    super().__init__()
