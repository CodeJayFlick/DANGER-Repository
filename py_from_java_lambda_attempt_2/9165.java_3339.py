Here is the translation of the given Java code into equivalent Python:

```Python
class BooleanField:
    MIN_VALUE = BooleanField(False)
    MAX_VALUE = BooleanField(True)

    def __init__(self):
        self.value = 0

    @classmethod
    def instance(cls):
        return cls.MIN_VALUE

    def set_null(self):
        super().setNull()
        self.value = 0

    def __init__(self, b=False, immutable=False):
        if immutable:
            super().__init__()
        else:
            super().__init__(False)
        self.value = int(b)

    @property
    def boolean_value(self):
        return bool(self.value)

    def set_boolean_value(self, b: bool):
        updating_primitive_value()
        self.value = 1 if b else 0

    def length(self) -> int:
        return 1

    def write(self, buf, offset=0) -> int:
        return buf.write_byte(offset, self.value)

    def read(self, buf, offset=0) -> int:
        updating_primitive_value()
        self.value = buf.read_byte(offset)
        return offset + 1

    @property
    def length_read(self):
        return 1

    def get_field_type(self) -> bytes:
        return b'\x01'

    def value_as_string(self) -> str:
        return str(self.boolean_value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BooleanField):
            return False
        return self.value == other.value

    def compare_to(self, o: 'BooleanField') -> int:
        f = BooleanField(o)
        if self.value == f.value:
            return 0
        elif self.value < f.value:
            return -1
        else:
            return 1

    @property
    def is_null(self) -> bool:
        return not self.boolean_value

    def copy_field(self):
        if self.is_null():
            return BooleanField()
        return BooleanField(self.boolean_value)

    def new_field(self):
        return BooleanField()

    @property
    def long_value(self) -> int:
        return self.value

    @property
    def binary_data(self) -> bytes:
        return [self.value]

    def set_binary_data(self, data: bytes):
        if len(data) != 1:
            raise IllegalFieldAccessException()
        updating_primitive_value()
        self.value = data[0]
```

Note that Python does not have an exact equivalent to Java's `byte` type. In this translation, I used the built-in integer types (`int`) and boolean values (`bool`).