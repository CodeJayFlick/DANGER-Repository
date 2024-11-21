class StringUTF8DataType:
    dataType = None  # Class variable

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("string-utf8", "utf8", "STRING", "STR", "s",
                         "String (Fixed Length UTF-8 Unicode)", 'UTF-8', None, StringLayoutEnum.FIXED_LEN)
        self.dataTypeManager = dtm

    def clone(self, dtm):
        if dtm == self.dataTypeManager:
            return self
        return StringUTF8DataType(dtm)

class AbstractStringDataType:  # Assuming this class exists in Python equivalent of the Java code.
    pass

class CharsetInfo:
    UTF8 = 'UTF-8'

class CharDataType:
    dataType = None  # Class variable

class StringLayoutEnum:
    FIXED_LEN = "Fixed Length"

# Usage
dtm = DataTypeManager()  # Assuming this class exists in Python equivalent of the Java code.
StringUTF8DataType.dataType = StringUTF8DataType(dtm)
