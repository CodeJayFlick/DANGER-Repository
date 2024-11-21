Here is the translation of the Java code into Python:

```Python
class DataTypeComponentImpl:
    def __init__(self, data_type: 'DataType', parent: 'CompositeDataTypeImpl' = None,
                 length: int = 0, ordinal: int = 0, offset: int = 0, field_name: str = '',
                 comment: str = '') -> None:
        self.parent = parent
        self.ordinal = ordinal
        self.offset = offset
        self.length = length
        self.field_name = field_name
        self.comment = comment
        self.data_type = data_type

    def is_bit_field_component(self) -> bool:
        return isinstance(self.data_type, BitFieldDataType)

    def is_zero_bit_field_component(self) -> bool:
        if self.is_bit_field_component():
            bit_field = self.data_type
            return bit_field.get_bit_size() == 0
        return False

    @property
    def offset(self) -> int:
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        self._offset = value

    @property
    def end_offset(self) -> int:
        if self.length == 0:
            return self.offset
        else:
            return self.offset + self.length - 1

    @property
    def comment(self) -> str:
        return self._comment

    @comment.setter
    def comment(self, value: str) -> None:
        self._comment = value

    @property
    def field_name(self) -> str:
        if self.is_zero_bit_field_component():
            return ''
        else:
            return self._field_name

    @field_name.setter
    def field_name(self, value: str) -> None:
        if value is not None:
            value = value.strip()
            if len(value) == 0 or value.lower() == 'default':
                value = None
            elif value.startswith('DEFAULT_'):
                try:
                    int(value[10:], 16)
                    raise DuplicateNameException("Reserved field name: " + value)
                except ValueError:
                    pass
        self._field_name = value

    @property
    def data_type(self) -> 'DataType':
        return self._data_type

    @data_type.setter
    def data_type(self, value: 'DataType') -> None:
        self._data_type = value

    @property
    def parent(self) -> 'CompositeDataTypeImpl':
        return self._parent

    @parent.setter
    def parent(self, value: 'CompositeDataTypeImpl') -> None:
        self._parent = value

    def update(self, ordinal: int, offset: int, length: int) -> None:
        self.ordinal = ordinal
        self.offset = offset
        self.length = length

    @property
    def length(self) -> int:
        return self._length

    @length.setter
    def length(self, value: int) -> None:
        self._length = value

    @property
    def ordinal(self) -> int:
        return self._ordinal

    @ordinal.setter
    def ordinal(self, value: int) -> None:
        self._ordinal = value

    @property
    def default_settings(self) -> 'Settings':
        if self._settings is None:
            self._settings = SettingsImpl()
        return self._settings

    @default_settings.setter
    def default_settings(self, value: 'Settings') -> None:
        self._settings = value

    def __eq__(self, other):
        if not isinstance(other, DataTypeComponent):
            return False
        my_dt = self.data_type
        other_dt = other.data_type
        parent_my_dt = self.parent
        aligned = (parent_my_dt is not None and isinstance(parent_my_dt, Composite) and parent_my_dt.is_packing_enabled())
        if ((not aligned and self.offset != other.offset) or
                self.length != other.length or
                self.ordinal != other.ordinal or
                self.field_name != other.field_name or
                self.comment != other.comment):
            return False

        # Component lengths need only be checked for dynamic types
        if self.length != other.length and isinstance(my_dt, Dynamic):
            return False

        return DataTypeUtilities.is_same_or_equivalent_data_type(my_dt, other_dt)

    def __hash__(self) -> int:
        return super().__hash__()
```

Note: The `Settings` class is not provided in the original Java code. Therefore, I have left it as a placeholder (`'Settings'`) for now.