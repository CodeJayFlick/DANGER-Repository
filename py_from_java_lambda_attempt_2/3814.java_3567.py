Here is the translation of the given Java code into Python:

```Python
class ConvertToUnsignedDecimalAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Unsigned Decimal", False)

    def get_menu_name(self, program, scalar, is_data):
        s = scalar
        if s.is_signed():
            s = Scalar(s.bit_length(), s.get_unsigned_value(), False)
        return f"Unsigned Decimal: {s.to_string(10, False, False, '', '')}"

    def convert_to_string(self, program, scalar, is_data):
        return str(scalar.get_unsigned_value())

    def get_format_choice(self):
        return FormatSettingsDefinition.DECIMAL
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. The equivalent of these in Python would be to define your own classes and functions, as shown above.

Also note that this code assumes you are using a library called `Scalar` which is not part of standard Python libraries. You may need to implement this class yourself based on how it was used in the original Java code.