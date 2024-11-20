Here is the translation of the Java code to Python:
```
class TerminatedUnicodeDataType:
    DATA_TYPE = None  # class variable

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("TerminatedUnicode", "unicode",
                         "Default Unicode Label", "Default Unicode Prefix",
                         "Default Unicode Abbrev Prefix",
                         "String (Null Terminated UTF-16 Unicode)",
                         "UTF-16", WideChar16DataType.DATA_TYPE,
                         StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, dtm)

    def clone(self):
        if self.get_data_type_manager() == get_data_type_manager():
            return self
        return TerminatedUnicodeDataType(get_data_type_manager())

class AbstractStringDataType:
    pass

class WideChar16DataType:
    DATA_TYPE = None  # class variable

class StringLayoutEnum:
    NULL_TERMINATED_UNBOUNDED = "Null Terminated Unbounded"

class CharsetInfo:
    UTF16 = "UTF-16"
```
Note that I had to create some Python classes (`AbstractStringDataType`, `WideChar16DataType`, and `StringLayoutEnum`) since there were no direct equivalents in the Java code. Additionally, I used Python's built-in string formatting capabilities instead of concatenating strings with `+` operators.

Also, please note that this is a translation of the provided Java code to Python, but it may not be an exact equivalent due to differences between the two languages and their respective ecosystems.