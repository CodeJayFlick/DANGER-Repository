Here is the translation of the Java code into Python:

```Python
class ConvertDecAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Decimal", "DEC")
        self.set_help_location(HelpLocation("DECOMPILER", "ActionConvert"))
        self.set_popup_menu_data(["Decimal"], "Decompile")

    def get_menu_prefix(self):
        return "Decimal: "

    def get_menu_display(self, value, size, is_signed):
        return self.get_equate_name(value, size, is_signed)

    def get_equate_name(self, value, size, is_signed, program=None):
        scalar = Scalar(size * 8, value)
        if is_signed:
            return str(scalar.signed_value())
        return str(scalar.unsigned_value())

class HelpLocation:
    def __init__(self, topic, location):
        self.topic = topic
        self.location = location

class MenuData:
    def __init__(self, menu_items, action_name):
        self.menu_items = menu_items
        self.action_name = action_name

class Scalar:
    def __init__(self, size, value):
        self.size = size
        self.value = value

    @property
    def signed_value(self):
        return self.value

    @property
    def unsigned_value(self):
        return self.value
```

Please note that Python does not have direct equivalent of Java's `long` type. In this translation, I used the built-in integer type (`int`) for simplicity. If you need to handle larger integers, consider using a library like `gmpy2`.