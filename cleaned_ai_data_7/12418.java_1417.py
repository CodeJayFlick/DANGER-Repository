class UnicodeDataType:
    DATA_TYPE = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("unicode", "unicode", "UNICODE", "UNI", "u",
                         "String (Fixed Length UTF-16 Unicode)", CharsetInfo.UTF16,
                         WideChar16DataType.DATA_TYPE, StringLayoutEnum.FIXED_LEN, dtm)

    def clone(self, dtm=None):
        if dtm == self.get_data_type_manager():
            return self
        return UnicodeDataType(dtm)


class AbstractStringDataType:
    pass


class CharsetInfo:
    UTF16 = None

class WideChar16DataType:
    DATA_TYPE = None

class StringLayoutEnum:
    FIXED_LEN = None

# Initialize the static variable
UnicodeDataType.DATA_TYPE = UnicodeDataType()
