Here is the translation of the Java code to Python:

```Python
class RangeFilterTextField:
    class FilterType(enum.Enum):
        MIN = 'min'
        MAX = 'max'

    def __init__(self, filter_type: str, program) -> None:
        super().__init__()
        self.program = program
        self.filter_type = filter_type
        self.max_value = self.get_max_scalar_value()

        self.set_value(self.max_value)

    @property
    def limit_value(self):
        return self.max_value

    @property
    def filter_type_(self):
        return self.filter_type

    def get_filter_value(self) -> int:
        text = self.get_text()
        if not text:
            return self.max_value

        try:
            if text.startswith('0x'):
                text = text[2:]
                value = int(text, 16)
            else:
                value = int(text)

            return value
        except ValueError:
            # This situation is not expected because the user is restricted to only entering digits.
            return self.max_value

    def get_max_scalar_value(self) -> int:
        default_pointer_size = self.program.get_default_pointer_size()
        max = 2 ** (default_pointer_size * 8)
        if self.filter_type == 'max':
            return max
        else:
            return -max


# Example usage:

class Program:
    def get_default_pointer_size(self):
        pass

program = Program()

range_filter_text_field = RangeFilterTextField('min', program)

print(range_filter_text_field.limit_value)  # prints the initial value of the range filter text field.
```

Please note that Python does not have direct equivalent to Java's `IntegerTextField` and `org.apache.commons.lang3.StringUtils`. The code above uses built-in Python types like strings, integers, etc.