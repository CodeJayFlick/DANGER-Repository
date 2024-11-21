class Unicode32DataType:
    data_type = None  # static instance variable

    def __init__(self):
        self.__init(None)

    def __init(self, dtm=None):
        super().__init__("unicode32", "unicode32", "UNICODE", "UNI", "u",
                         "String (Fixed Length UTF-32 Unicode)", CharsetInfo.UTF32,
                         WideChar32DataType.data_type, StringLayoutEnum.FIXED_LEN, dtm)

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Unicode32DataType(dtm)


class AbstractStringDataType:
    pass


class DataTypeManager:
    pass


class CharsetInfo:
    UTF32 = None  # static instance variable


class WideChar32DataType:
    data_type = None  # static instance variable


class StringLayoutEnum:
    FIXED_LEN = None  # static instance variable
