Here is the translation of the given Java code into equivalent Python:

```Python
class ConvertToDoubleAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Double", False)

    def get_menu_name(self, program, scalar, is_data):
        value_string = self.convert_to_string(program, scalar, is_data)
        if value_string is None:
            return None
        return f"Double: {value_string}"

    @staticmethod
    def value(program, s):
        try:
            data_organization = program.data_type_manager.get_data_organization()
            format_ = FloatFormatFactory().get_float_format(data_organization.double_size())
            return format_.round(format_.host_float(s.bigInteger()))
        except UnsupportedFloatFormatException as e:
            return None

    def convert_to_string(self, program, scalar, is_data):
        if is_data:
            return None  # unsupported
        value = self.value(program, scalar)
        return str(value) if value else None

    @staticmethod
    def get_format_choice():
        return -1  # unsupported for data


# Example usage:

class EquatePlugin:
    pass

plugin = EquatePlugin()
action = ConvertToDoubleAction(plugin)

program = "Program"  # Assuming this is a Program object in Python.
scalar = "Scalar"  # Assuming this is a Scalar object in Python.

print(action.get_menu_name(program, scalar, False))
```

Please note that the above code assumes you have equivalent classes and methods for `EquatePlugin`, `Program` and `Scalar`. The actual implementation of these would depend on your specific use case.