class FormatSettingsDefinition:
    HEX = 0
    DECIMAL = 1
    BINARY = 2
    OCTAL = 3
    CHAR = 4

    choices = ["hex", "decimal", "binary", "octal", "char"]
    radix = [16, 10, 2, 8, 0]

    FORMAT = "format"

    DEF_CHAR = FormatSettingsDefinition(CHAR)
    DEF_HEX = FormatSettingsDefinition(HEX)
    DEF_DECIMAL = FormatSettingsDefinition(DECIMAL)

    DEF = DEF HEX

    def __init__(self, default_format):
        self.default_format = default_format

    def get_format(self, settings=None):
        if settings is None:
            return self.default_format
        value = settings.get(FORMAT)
        if value is None:
            return self.default_format
        format_value = int(value)
        if (format_value < 0) or (format_value > CHAR):
            return HEX
        return format_value

    def get_radix(self, settings=None):
        try:
            return self.radix[self.get_format(settings)]
        except IndexError:
            return 16

    def get_choice(self, settings=None):
        return self.get_format(settings)

    def set_choice(self, settings, value):
        if (value < 0) or (value > CHAR):
            settings.clear(FORMAT)
        else:
            settings.set(FORMAT, value)

    def display_choices(self, settings=None):
        return self.choices

    def get_name(self):
        return "Format"

    def get_description(self):
        return "Selects the display format"

    def get_display_choice(self, value, settings=None):
        return self.choices[value]

    def clear(self, settings):
        settings.clear(FORMAT)

    def copy_setting(self, settings, dest_settings):
        l = settings.get(FORMAT)
        if l is None:
            dest_settings.clear(FORMAT)
        else:
            dest_settings.set(FORMAT, l)

    def has_value(self, setting):
        return setting.get(FORMAT) != None

    def get_display_choice_from_setting(self, settings=None):
        return self.choices[self.get_choice(settings)]

    def set_display_choice(self, settings, choice):
        for i in range(len(self.choices)):
            if self.choices[i] == choice:
                self.set_choice(settings, i)
                break
