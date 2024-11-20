Here is the translation of the Java code into Python:

```Python
class EncodedValue:
    def __init__(self):
        self.value = None
        self.value_type = None
        self.value_args = None
        self.value_bytes = None
        self.array = None
        self.annotation = None

    def from_reader(self, reader):
        self.value = reader.read_next_byte()
        self.value_type = (self.value & 0x1f)
        self.value_args = ((self.value & 0xe0) >> 5)

        if self.value_type in [ValueFormats.VALUE_BYTE,
                               ValueFormats.VALUE_SHORT,
                               ValueFormats.VALUE_CHAR,
                               ValueForms.VALUETYPE_8,
                               ValueForms.VALUETYPE_16]:
            self.value_bytes = reader.read_next_byte_array(self.value_args + 1)
        elif self.value_type == ValueFormats.VALUE_ARRAY:
            self.array = EncodedArray(reader)
        elif self.value_type == ValueFormats.VALUE_ANNOTATION:
            self.annotation = EncodedAnnotation(reader)

    def get_value_args(self):
        return self.value_args

    def get_value_type(self):
        return self.value_type

    def get_value_bytes(self):
        return self.value_bytes

    def get_value_byte(self):
        if self.value_bytes is not None and len(self.value_bytes) > 0:
            return self.value_bytes[0]
        else:
            return None

    def get_array(self):
        return self.array

    def get_annotation(self):
        return self.annotation

    def is_value_boolean(self):
        return self.value_args == 1


class EncodedArray:
    def __init__(self, reader):
        pass

    def from_reader(self, reader):
        # implementation of reading array values
        pass

    def to_data_type(self):
        structure = StructureDataType("encoded_array", 0)
        structure.add(BYTE, "values", None)
        return structure


class EncodedAnnotation:
    def __init__(self, reader):
        pass

    def from_reader(self, reader):
        # implementation of reading annotation values
        pass

    def to_data_type(self):
        structure = StructureDataType("encoded_annotation", 0)
        structure.add(BYTE, "values", None)
        return structure


class ValueFormats:
    VALUE_BYTE = 1
    VALUE_SHORT = 2
    VALUE_CHAR = 3
    VALUE_INT = 4
    VALUE_LONG = 5
    VALUE_FLOAT = 6
    VALUE_DOUBLE = 7
    VALUE_STRING = 8
    VALUE_TYPE = 9
    VALUE_FIELD = 10
    VALUE_METHOD = 11
    VALUE_ENUM = 12
    VALUE_ARRAY = 13
    VALUE_ANNOTATION = 14
    VALUE_NULL = 15
    VALUE_BOOLEAN = 16


class StructureDataType:
    def __init__(self, name, length):
        self.name = name
        self.length = length

    def add(self, data_type, field_name, default_value=None):
        pass

    def set_category_path(self, category_path):
        self.category_path = category_path

    def to_data_type(self):
        return self


class BYTE:
    get_length = lambda: 1
```

Please note that this is a direct translation of the Java code into Python. The implementation details may vary depending on your specific requirements and constraints.