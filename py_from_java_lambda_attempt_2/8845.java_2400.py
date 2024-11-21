Here is the translation of the given Java code into Python:

```Python
class DataTypeStringable:
    SHORT_NAME = "DT"

    def __init__(self):
        self.managerUniversalID = None
        self.dataTypeID = None
        self.dataTypeName = ""
        self.length = 0
        super().__init__(SHORT_NAME)

    def __init__(self, data_type: 'DataType', data_type_manager: 'DataTypeManager', length: int):
        super().__init__(SHORT_NAME)
        universal_id = data_type_manager.get_universal_id()
        self.managerUniversalID = universal_id.value
        self.dataTypeID = data_type_manager.get_id(data_type)
        self.dataTypeName = data_type.name
        self.length = length

    def get_display_string(self):
        return f"{self.dataTypeName} (size={self.length})"

    def do_convert_to_string(self, program: 'Program'):
        return f"{self.managerUniversalID}{DELIMITER}{self.dataTypeID}{DELIMITER}{self.dataTypeName}{DELIMITER}{str(self.length)}"

    def do_restore_from_string(self, string: str, program: 'Program'):
        tokenizer = StringTokenizer(string, DELIMITER)
        self.managerUniversalID = int(tokenizer.next_token())
        self.dataTypeID = int(tokenizer.next_token())
        self.dataTypeName = tokenizer.next_token()
        self.length = int(tokenizer.next_token())

    def get_data_type_manager_id(self):
        return self.managerUniversalID

    def get_data_type_id(self):
        return self.dataTypeID

    def get_data_type_name(self):
        return self.dataTypeName

    def get_data_type(self, data_type_manager: 'DataTypeManager'):
        actual_universal_id = data_type_manager.get_universal_id().value
        if actual_universal_id != self.managerUniversalID:
            raise AssertException(f"Provided data type manager ID of {actual_universal_id} doesn't matched saved ID of {self.managerUniversalID}.")
        return data_type_manager.get_data_type(self.dataTypeID)

    def get_length(self):
        return self.length

    def __eq__(self, other: 'DataTypeStringable'):
        if self is other:
            return True
        if (other is None) or not isinstance(other, DataTypeStringable):
            return False
        return self.managerUniversalID == other.managerUniversalID and \
               self.dataTypeID == other.dataTypeID and \
               self.dataTypeName == other.dataTypeName and \
               self.length == other.length

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + (int(self.dataTypeID) ^ ((int(self.dataTypeID)) >> 32))
        if self.dataTypeName:
            result = prime * result + hash(self.dataTypeName)
        else:
            result = prime * result + 0
        result = prime * result + int(self.managerUniversalID) ^ ((int(self.managerUniversalID)) >> 32)
        result = prime * result + self.length
        return result

DELIMITER = ","
```

Please note that Python does not have direct equivalent of Java's `StringTokenizer` class. Instead, you can use the built-in string methods like `split()` or a library like `pyparsing`.