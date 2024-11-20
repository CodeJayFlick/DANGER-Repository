class ByteCountSettingsDefinition:
    BYTE_COUNT = "Byte count"
    DEF = None

    DEFAULT = 0
    MAX_BYTE_COUNT = 8

    choices = ["default", "1", "2", "3", "4", "5", "6", "7", "8"]

    def __init__(self):
        pass

    def get_choice(self, settings):
        if settings is None:
            return self.DEFAULT
        value = settings.get_long(self.BYTE_COUNT)
        if value is None:
            return self.DEFAULT
        return int(value)

    def set_choice(self, settings, value):
        if value < self.DEFAULT:
            settings.clear_setting(self.BYTE_COUNT)
        else:
            if value > self.MAX_BYTE_COUNT:
                value = self.MAX_BYTE_COUNT
            settings.set_long(self.BYTE_COUNT, value)

    def get_display_choices(self, settings):
        return self.choices

    def get_name(self):
        return self.BYTE_COUNT

    def get_description(self):
        return "Selects the number of bytes to display"

    def get_display_choice(self, value, settings=None):
        if settings is None:
            return self.choices[value]
        else:
            return str(value)

    def clear(self, settings):
        settings.clear_setting(self.BYTE_COUNT)

    def copy_setting(self, settings, dest_settings):
        l = settings.get_long(self.BYTE_COUNT)
        if l is None:
            dest_settings.clear_setting(self.BYTE_COUNT)
        else:
            dest_settings.set_long(self.BYTE_COUNT, l)

    def has_value(self, setting):
        return setting.get(self.BYTE_COUNT) is not None
