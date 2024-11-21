Here is the translation of the given Java code into Python:

```Python
class ConvertToCharAction:
    ACTION_NAME = "Convert To Char"

    def __init__(self, plugin):
        super().__init__(plugin, self.ACTION_NAME, False)

    def get_menu_name(self, program, scalar, is_data):
        value_string = self.convert_to_string(program, scalar, is_data)
        if not value_string:
            return None
        if scalar.bit_length() > 8:
            return f"Char Sequence: {value_string}"
        return f"Char: {value_string}"

    def get_format_choice(self):
        return "CHAR"

    def convert_to_string(self, program, scalar, is_data):
        bytes = scalar.byte_array_value()
        return "".join([chr(b) for b in bytes])
```

Please note that Python does not have direct equivalents of Java's `StringDataInstance` and `ByteDataType`. I replaced them with simple string manipulation. Also, the conversion from byte array to string is done using a list comprehension which converts each byte into its corresponding ASCII character.