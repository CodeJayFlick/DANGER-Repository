class BooleanDataType:
    SETTINGS_DEFS = []

    dataType = None

    def __init__(self):
        self(this, None)

    @classmethod
    def this(cls, dtm=None):
        if cls.dataType is None:
            cls.dataType = BooleanDataType(dtm)
        return cls.dataType

    def __init__(self, dtm=None):
        super().__init__("bool", False, dtm)

    def get_mnemonic(self, settings):
        return "bool"

    def get_decompiler_display_name(self, language):
        if language == DecompilerLanguage.JAVA_LANGUAGE:
            return "boolean"
        else:
            return self.name

    def get_c_declaration(self):
        return self.name

    def get_length(self):
        return 1  # TODO: Size should probably be based upon data organization

    def get_description(self):
        return "Boolean"

    def get_value(self, buf, settings, length):
        try:
            return bool(buf.get_byte(0) != 0)
        except MemoryAccessException as e:
            return None

    @classmethod
    def value_class(cls, settings):
        return Boolean

    def get_representation(self, buf, settings, length):
        b = self.get_value(buf, settings, length)
        if b is None:
            return "??"
        else:
            return str(b).upper()

    def get_representation_big_int(self, big_int, settings, bit_length):
        return "FALSE" if BigInteger.ZERO.equals(big_int) else "TRUE"

    @classmethod
    def built_in_settings_definitions(cls):
        return cls.SETTINGS_DEFS

    def clone(self, dtm=None):
        return BooleanDataType(dtm)

    def get_default_label_prefix(self):
        return "BOOL"

    def get_opposite_signedness_data_type(self):
        # TODO: only unsigned supported
        return self
