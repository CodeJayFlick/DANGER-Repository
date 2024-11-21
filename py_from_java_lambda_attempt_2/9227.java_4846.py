Here is the translation of the Java code into Python:

```Python
class IntField:
    MIN_VALUE = IntField(0x80000000, True)
    MAX_VALUE = IntField(0x7fffffff, True)
    ZERO_VALUE = IntField(0, True)

    def __init__(self):
        self.value = 0

    def __init__(self, i, immutable=False):
        super().__init__()
        self.value = i
        self.immutable = immutable

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v):
        if not self.immutable:
            self._value = v
        else:
            raise ValueError("Immutable field")

    def set_null(self):
        super().setNull()
        self.value = 0

    def get_value(self):
        return self.value

    def set_value(self, value):
        updating_primitive_value()
        self.value = value

    @property
    def length(self):
        return 4

    def write(self, buf, offset) -> int:
        return buf.put_int(offset, self.value)

    def read(self, buf, offset) -> int:
        updating_primitive_value()
        self.value = buf.get_int(offset)
        return offset + 4

    @property
    def field_type(self):
        return "INT"

    def get_as_string(self):
        return f"0x{self.value:08X}"

    def __eq__(self, other):
        if not isinstance(other, IntField):
            return False
        return self.value == other.value

    def compare_to(self, o) -> int:
        if isinstance(o, IntField):
            if self.value == o.value:
                return 0
            elif self.value < o.value:
                return -1
            else:
                return 1
        raise ValueError("Invalid type")

    @property
    def min_value(self):
        return MIN_VALUE

    @property
    def max_value(self):
        return MAX_VALUE


class PrimitiveField(IntField):

    def __init__(self, immutable=False):
        self.immutable = immutable

    def updating_primitive_value(self):
        pass  # No-op for IntField


# Usage example:
field = IntField(123)
print(field.get_as_string())  # Output: "0x7B"
```

Please note that Python does not have direct equivalent of Java's `Buffer` class. I replaced it with the built-in file-like object (`buf`) in the `write()` and `read()` methods, assuming you want to write/read from a buffer.