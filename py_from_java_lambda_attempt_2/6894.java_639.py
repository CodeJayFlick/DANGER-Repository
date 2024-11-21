Here is the equivalent Python code:

```Python
class ConvertBinaryAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Binary", 0)
        self.set_help_location("Decompile")
        self.set_popup_menu_data(["Binary"], "Decompile")

    def get_menu_prefix(self):
        return "Binary: "

    def get_menu_display(self, value, size, is_signed):
        scalar = Scalar(size * 8, value)
        v = scalar.get_value()
        if not is_signed:
            v = abs(v)

        bit_string = bin(v)[2:]
        bit_len = len(bit_string)
        if bit_len <= 8:
            bit_len = 8
        elif bit_len <= 16:
            bit_len = 16
        elif bit_len <= 32:
            bit_len = 32
        else:
            bit_len = 64

        return f"0b{bit_string.zfill(bit_len)}"

    def get_equate_name(self, value, size, is_signed, program):
        value_str = bin(value)[2:]
        value_str = value_str.zfill(size * 8)
        return f"{value_str}b"
```

Note that Python does not have direct equivalents for Java classes like `MenuData`, `HelpLocation`, and `StringUtilities`. I've replaced them with simpler constructs. Also, the equivalent of Java's `@Override` annotation is not present in Python; it's a convention to use the same method name as the parent class if you're overriding a method.