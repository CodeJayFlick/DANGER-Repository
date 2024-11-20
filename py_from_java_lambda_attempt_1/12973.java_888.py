Here is the translation of the given Java code into Python:

```Python
class SettingsBuilder:
    def __init__(self):
        self.settings = {}

    def set_charset(self, cs: str) -> 'SettingsBuilder':
        self.settings['charset'] = cs
        return self

    def set_render_unicode_settings(self, ruenum: int) -> 'SettingsBuilder':
        self.settings['render_unicode_settings'] = ruenum
        return self

    def set_translation_settings(self, tenum: int) -> 'SettingsBuilder':
        self.settings['translation_settings'] = tenum
        return self

    def get_long(self, name: str):
        if name in self.settings:
            return long(self.settings[name])
        else:
            return None

    def get_string(self, name: str):
        if name in self.settings:
            return str(self.settings[name])
        else:
            return None

    def get_byte_array(self, name: str):
        if name in self.settings:
            return bytes(self.settings[name])
        else:
            return None

    def get_value(self, name: str):
        if name in self.settings:
            return self.settings[name]
        else:
            return None

    def set_long(self, name: str, value: int) -> 'SettingsBuilder':
        self.settings[name] = value
        return self

    def set_string(self, name: str, value: str) -> 'SettingsBuilder':
        self.settings[name] = value
        return self

    def set_byte_array(self, name: str, value: bytes) -> 'SettingsBuilder':
        self.settings[name] = value
        return self

    def set_value(self, name: str, value: object) -> 'SettingsBuilder':
        self.settings[name] = value
        return self

    def clear_setting(self, name: str):
        if name in self.settings:
            del self.settings[name]

    def clear_all_settings(self):
        self.settings.clear()

    def get_names(self):
        return list(self.settings.keys())

    def is_empty(self):
        return not bool(self.settings)

    def get_default_settings(self):
        return self.settings.copy()
```

Note that Python does not have direct equivalents for Java's `Charset`, `RenderUnicodeSettingsDefinition` and `TranslationSettingsDefinition`. I've replaced them with simple string values in the above code.