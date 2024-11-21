Here is the equivalent Python code:

```Python
class ConvertOctAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Octal", 8)
        self.set_help_location("ActionConvert")
        self.set_popup_menu_data(["Octal"], "Decompile")

    def get_menu_prefix(self):
        return "Octal: "

    def get_menu_display(self, value, size, is_signed):
        scalar = Scalar(size * 8, value)
        if is_signed:
            v = scalar.get_signed_value()
            value_str = format(v, 'o')
            if v < 0:
                # use of substring removes '-' prefix for negative value
                return "-0" + value_str[1:]
            else:
                return "0" + value_str
        else:
            return "0" + scalar.get_unsigned_value().to_octal_string()

    def get_equate_name(self, value, size, is_signed, program):
        scalar = Scalar(size * 8, value)
        return scalar.get_unsigned_value().to_octal_string() + 'o'
```

Note that Python does not have direct equivalents for Java classes like `DecompilePlugin`, `Program`, and `Scalar`. These are likely custom classes specific to the Ghidra decompiler. I've replaced them with placeholder variables or methods in this translation, as they do not seem to be essential to the functionality of the action.