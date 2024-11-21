class CodeUnitCountSettingsDefinition:
    CODE_UNIT_COUNT = "Code-unit count"
    DEF = None  # This will be set later when an instance is created

    MAX_CODE_UNIT_COUNT = 8

    choices = ["1", "2", "3", "4", "5", "6", "7", "8"]

    def __init__(self):
        pass

    @staticmethod
    def get_count(settings):
        return CodeUnitCountSettingsDefinition.get_choice(settings) + 1

    @classmethod
    def set_count(cls, settings, count):
        if count < 1:
            settings.clear(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)
        else:
            if count > cls.MAX_CODE_UNIT_COUNT:
                count = cls.MAX_CODE_UNIT_COUNT
            settings.set_long(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT, count - 1)

    @classmethod
    def get_choice(cls, settings):
        if settings is None:
            return 0
        value = settings.get_long(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)
        if value is None:
            return 0
        return int(value)

    @classmethod
    def set_choice(cls, settings, value):
        if value < 0:
            settings.clear(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)
        else:
            if value > len(cls.choices) - 1:
                value = len(cls.choices) - 1
            settings.set_long(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT, int(value))

    @classmethod
    def get_display_value(cls, settings):
        return cls.choices[cls.get_choice(settings)]

    @classmethod
    def get_display_choices(cls, settings):
        return cls.choices

    @classmethod
    def get_name(cls):
        return CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT

    @classmethod
    def get_description(cls):
        return "Selects the number of bytes to display"

    @classmethod
    def get_display_choice(cls, value, settings):
        return cls.choices[value]

    @classmethod
    def clear(cls, settings):
        settings.clear(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)

    @classmethod
    def copy_setting(cls, settings, dest_settings):
        l = settings.get_long(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)
        if l is None:
            dest_settings.clear(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT)
        else:
            dest_settings.set_long(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT, int(l))

    @classmethod
    def has_value(cls, setting):
        return setting.get(CodeUnitCountSettingsDefinition.CODE_UNIT_COUNT) is not None

# Create an instance of the class to use its methods
CodeUnitCountSettingsDefinition.DEF = CodeUnitCountSettingsDefinition()
