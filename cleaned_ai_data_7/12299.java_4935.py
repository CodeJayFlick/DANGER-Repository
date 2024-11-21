class EndianSettingsDefinition:
    choices = ["default", "little", "big"]
    ENDIAN_SETTING_NAME = "endian"

    DEF = None
    ENDIAN = None
    DEFAULT = 0
    LITTLE = 1
    BIG = 2

    def __init__(self):
        pass

    @staticmethod
    def is_big_endian(settings, buf):
        val = settings.get(ENDIAN_SETTINGS_NAME)
        if val == EndianSettingsDefinition.DEFAULT:
            return buf.is_big_endian()
        else:
            return val == EndianSettingsDefinition.BIG

    @staticmethod
    def get_endianness(settings, default_value=None):
        val = settings.get(ENDIAN_SETTING_NAME)
        if val is None:
            return default_value
        elif val == EndianSettingsDefinition.DEFAULT:
            return default_value
        else:
            return {"big": Endian.BIG, "little": Endian.LITTLE}[val]

    @staticmethod
    def set_big_endian(settings, is_big_endian):
        settings.set(ENDIAN_SETTING_NAME, 1 if is_big_endian else 0)

    @classmethod
    def get_choice(cls, settings):
        if settings is None:
            return cls.DEFAULT
        value = settings.get(cls.ENDIAN_SETTING_NAME)
        if value is None:
            return cls.DEFAULT
        val = int(value)
        if val < cls.DEFAULT or val > cls.BIG:
            val = cls.DEFAULT
        return val

    @classmethod
    def set_choice(cls, settings, value):
        settings.set(cls.ENDIAN_SETTING_NAME, str(value))

    @classmethod
    def get_display_choices(cls, settings):
        return cls.choices

    @classmethod
    def get_name(cls):
        return "Endian"

    @classmethod
    def get_description(cls):
        return "Selects the endianess of the data"

    @classmethod
    def get_display_choice(cls, value, settings):
        return cls.choices[value]

    @classmethod
    def clear(cls, settings):
        settings.clear_setting(cls.ENDIAN_SETTING_NAME)

    @classmethod
    def copy_settings(cls, settings, dest_settings):
        val = settings.get(cls.ENDIAN_SETTING_NAME)
        if val is None:
            dest_settings.set(cls.ENDIAN_SETTING_NAME, None)
        else:
            dest_settings.set(cls.ENDIAN_SETTING_NAME, val)

    @classmethod
    def has_value(cls, setting):
        return setting.get(cls.ENDIAN_SETTING_NAME) is not None

# Usage example:

settings = {"default": 0, "little": 1, "big": 2}
buf = MemBuffer()  # Assuming this class exists in your Python code.

print(EndianSettingsDefinition.is_big_endian(settings, buf))  # prints the value of settings["endian"] if it's not None; otherwise returns buf.is_big_endian()
