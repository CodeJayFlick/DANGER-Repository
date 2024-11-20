Here is the translation of the Java code into Python:

```Python
class ReadOnlyDataTypeComponent:
    def __init__(self, data_type: 'DataType', parent: 'DynamicDataType', length: int, ordinal: int, offset: int, field_name: str = None, comment: str = None):
        self.data_type = data_type
        self.parent = parent
        self.ordinal = ordinal
        self.offset = offset
        self.length = length
        self.field_name = field_name if field_name else f"field_{ordinal}"
        self.comment = comment

    def is_bit_field_component(self) -> bool:
        return isinstance(self.data_type, BitFieldDataType)

    def is_zero_bit_field_component(self) -> bool:
        if isinstance(self.data_type, BitFieldDataType):
            return (self.data_type.get_bit_size() == 0)
        return False

    @property
    def offset_(self) -> int:
        return self.offset

    @property
    def end_offset_(self) -> int:
        return self.offset + self.length - 1

    @property
    def comment_(self) -> str:
        return self.comment

    def set_comment(self, value: str):
        pass  # read-only

    @property
    def field_name_(self) -> str:
        if not self.field_name:
            self.field_name = f"field_{self.ordinal}"
        return self.field_name_

    def get_default_field_name(self) -> str:
        return f"field_{self.ordinal}"

    def set_field_name(self, value: str):
        pass  # read-only

    @property
    def data_type_(self) -> 'DataType':
        return self.data_type

    @property
    def parent_(self) -> 'DynamicDataType':
        return self.parent

    @property
    def length_(self) -> int:
        if not self.length:
            return 1
        return self.length_

    @property
    def ordinal_(self) -> int:
        return self.ordinal

    @property
    def default_settings(self) -> 'Settings':
        settings = SettingsImpl()
        return settings

    def set_default_settings(self, value: 'Settings'):
        pass  # read-only

    def __eq__(self, other):
        if not isinstance(other, ReadOnlyDataTypeComponent):
            return False
        dtc = other
        if self.offset != dtc.offset or self.length != dtc.length or self.ordinal != dtc.ordinal:
            return False
        if not self.data_type.is_equivalent(dtc.data_type):
            return False
        return (self.field_name == dtc.field_name) and (self.comment == dtc.comment)

    def is_equivalent(self, other: 'ReadOnlyDataTypeComponent') -> bool:
        my_dt = self.data_type_
        other_dt = other.data_type_
        if not DataTypeUtilities.is_same_or_equivalent_data_type(my_dt, other_dt):
            return False
        # Components don't need to have matching offset when they are aligned, only matching ordinal.
        if (not ((self.parent_ and isinstance(self.parent_, Composite)) or (other.parent_ and isinstance(other.parent_, Composite)))) \
                and self.offset != dtc.offset:
            return False
        # Components don't need to have matching length when they are aligned. Is this correct?
        if not ((self.parent_ and isinstance(self.parent_, Composite)) or (other.parent_ and isinstance(other.parent_, Composite))) \
                and self.length != other_dt.get_length():
            return False
        if self.ordinal != dtc.ordinal:
            return False
        # if they contain datatypes that have same ids, then we are essentially equivalent.
        return True

    @staticmethod
    def is_same_string(s1: str, s2: str) -> bool:
        if not s1:
            return not s2
        return s1 == s2


class SettingsImpl:

    pass  # implement your settings class here