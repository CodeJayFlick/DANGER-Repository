Here is the equivalent Python code:

```Python
class ConvertToBinaryAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Unsigned Binary", False)

    def get_menu_name(self, program, scalar, is_data):
        return f"Unsigned Binary: {self.convert_to_string(program, scalar, is_data)}"

    def convert_to_string(self, program, scalar, is_data):
        value_str = bin(scalar.get_unsigned_value())[2:]
        value_str = '0' * (scalar.bit_length() - len(value_str)) + value_str
        return f"{value_str}b"
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the concept of a class extending another. The equivalent code is written in pure Python and does not require any additional libraries or modules to run.