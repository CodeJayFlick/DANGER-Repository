Here is the translation of the given Java code into Python:

```Python
class PaddingSettingsDefinition:
    PADDED_VALUE = 1
    UNPADDED_VALUE = 0
    CHOICES = ["unpadded", "padded"]
    PADDED = "padded"

    DEF = PaddingSettingsDefinition()

    def __init__(self):
        pass

    def is_padded(self, settings):
        if settings is None:
            return False
        value = settings.get("PADDING")
        if value is None:
            return False
        return value != self.UNPADDED_VALUE

    def set_padded(self, settings, is_padded):
        if is_padded:
            self.set_choice(settings, self.PADDED_VALUE)
        else:
            self.set_choice(settings, self.UNPADDED_VALUE)

    def get_choice(self, settings):
        if self.is_padded(settings):
            return self.PADDED_VALUE
        return self.UNPADDED_VALUE

    def set_choice(self, settings, value):
        settings["PADDING"] = value

    def display_choices(self, settings):
        return self.CHOICES

    def get_name(self):
        return "Padding"

    def get_description(self):
        return "Selects if the data is padded or not"

    def get_display_choice(self, value, settings):
        return self.CHOICES[value]

    def clear(self, settings):
        del settings["PADDING"]

    def copy_setting(self, settings, dest_settings):
        value = settings.get("PADDING")
        if value is None:
            dest_settings.clear()
        else:
            dest_settings["PADDING"] = value

    def has_value(self, setting):
        return "PADDING" in setting
```

Please note that Python does not have direct equivalent of Java's `EnumSettingsDefinition` and other classes. This code uses simple class definition to mimic the functionality provided by those classes.