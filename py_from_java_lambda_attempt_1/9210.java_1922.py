Here is the translation of the Java code into Python:

```Python
class Field:
    EMPTY_ARRAY = []

    BYTE_TYPE = 0
    SHORT_TYPE = 1
    INT_TYPE = 2
    LONG_TYPE = 3
    STRING_TYPE = 4
    BINARY_OBJ_TYPE = 5
    BOOLEAN_TYPE = 6
    FIXED_10_TYPE = 7

    LEGACY_INDEX_LONG_TYPE = 8

    FIELD_TYPE_MASK = 0x0F
    INDEX_PRIMARY_KEY_TYPE_MASK = ~FIELD_TYPE_MASK | (1 << 4)

    def __init__(self, immutable=False):
        self.immutable = immutable

    def check_immutable(self):
        if self.immutable:
            raise IllegalFieldAccessException("Immutable field instance")

    def get_long_value(self):
        raise IllegalFieldAccessException()

    def set_long_value(self, value):
        raise IllegalFieldAccessException()

    def get_int_value(self):
        raise IllegalFieldAccessException()

    def set_int_value(self, value):
        raise IllegalFieldAccessException()

    def get_short_value(self):
        raise IllegalFieldAccessException()

    def set_short_value(self, value):
        raise IllegalFieldAccessException()

    def get_byte_value(self):
        raise IllegalFieldAccessException()

    def set_byte_value(self, value):
        raise IllegalFieldAccessException()

    def get_boolean_value(self):
        raise IllegalFieldAccessException()

    def set_boolean_value(self, value):
        raise IllegalFieldAccessException()

    def get_binary_data(self):
        raise NotImplementedError("Method not implemented")

    def set_binary_data(self, bytes):
        raise NotImplementedError("Method not implemented")

    def __str__(self):
        return "Abstract Field"

class UnsupportedFieldException(Exception):
    pass

def get_field(field_type: int) -> 'Field':
    if field_type == 0x88:
        raise UnsupportedFieldException(0x88)
    elif (field_type & INDEX_PRIMARY_KEY_TYPE_MASK) != 0:
        return IndexField.get_index_field(field_type)
    else:
        switcher = {
            Field.LONG_TYPE: LongField,
            Field.INT_TYPE: IntField,
            Field.STRING_TYPE: StringField,
            Field.SHORT_TYPE: ShortField,
            Field.BYTE_TYPE: ByteField,
            Field.BOOLEAN_TYPE: BooleanField,
            Field.BINARY_OBJ_TYPE: BinaryField,
            Field.FIXED_10_TYPE: FixedField10
        }
        return switcher.get(field_type & FIELD_TYPE_MASK, lambda: None)()

def get_fixed_field(fixed_length: int):
    if fixed_length == 10:
        return FixedField10()
    else:
        raise ValueError("Unsupported fixed- field length")

class IllegalFieldAccessException(Exception):
    pass

# Note that the above code is not complete. The abstract methods in Field class should be implemented by its subclasses.
```

This Python translation does not include all of the Java code, as some parts are not directly translatable (e.g., `getMinValue`, `getMaxValue` and their implementations).