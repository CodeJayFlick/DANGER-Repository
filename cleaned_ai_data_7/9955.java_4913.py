class FloatingPointPrecisionSettingsDefinition:
    PRECISION_DIGITS = "Precision digits"
    DEFAULT_PRECISION = 3
    MAX_PRECISION = len(choices) - 2
    
    def __init__(self):
        pass

    def get_precision(self, settings):
        return self.get_choice(settings) - 1

    def set_precision(self, settings, digits):
        self.set_choice(settings, digits + 1)

    def get_choice(self, settings):
        value = DEFAULT_PRECISION + 1
        if settings is not None:
            value = settings.get(PRECISION_DIGITS)
            if value is None:
                value = DEFAULT_PRECISION + 1
        return int(value)

    def set_choice(self, settings, value_index):
        if value_index < 0:
            settings.clear_setting(PRECISION_DIGITS)
        else:
            if value_index == 0:
                value_index = DEFAULT_PRECISION + 1
            elif value_index > MAX_PRECISION + 1:
                value_index = MAX_PRECISION + 1
            settings.set_long(PRECISION_DIGITS, int(value_index))

    def get_display_choices(self, settings):
        return choices

    def get_name(self):
        return PRECISION_DIGITS

    def get_description(self):
        return "Selects the number of digits of precision to display"

    def get_choice_by_display_choice(self, display_choice, settings):
        for i in range(len(choices)):
            if choices[i] == display_choice:
                return i
        return -1

    def get_display_choice(self, value, settings):
        return choices[value]

    def clear(self, settings):
        settings.clear_setting(PRECISION_DIGITS)

    def copy_setting(self, settings, dest_settings):
        l = settings.get_long(PRECISION_DIGITS)
        if l is None:
            dest_settings.clear_setting(PRECISION_DIGITS)
        else:
            dest_settings.set_long(PRECISION_DIGITS, int(l))

    def has_value(self, setting):
        return setting.get(PRECISION_DIGITS) is not None


choices = ["default", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
