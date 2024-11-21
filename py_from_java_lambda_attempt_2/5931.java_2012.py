Here is the equivalent Python code:

```Python
class FunctionThunkSettingsDefinition:
    DEF = None

    THUNK = "Show thunk"
    NAME = THUNK
    DESCRIPTION = f"On signals to show the thunk function attribute when present"

    DEFAULT = True

    def __init__(self):
        if not hasattr(self, 'DEF'):
            self.DEF = self()

    def get_value(self, settings=None):
        if settings is None:
            return self.DEFAULT
        value = settings.get(self.THUNK)
        if value is None:
            return self.DEFAULT
        return bool(value)

    def set_value(self, settings, value):
        settings[self.THUNK] = str(value).lower()

    def copy_setting(self, src_settings, dest_settings):
        value = src_settings.get(self.THUNK)
        if value is None:
            del dest_settings[self.THUNK]
        else:
            dest_settings[self.THUNK] = value

    def clear(self, settings):
        del settings[self.THUNK]

    @property
    def description(self):
        return self.DESCRIPTION

    @property
    def name(self):
        return self.NAME

    def has_value(self, settings):
        return self.THUNK in settings and settings.get(self.THUNK) is not None


# Usage:
settings = {}
fts_def = FunctionThunkSettingsDefinition()
print(fts_def.name)
fts_def.set_value(settings, True)
print(fts_def.get_value(settings))
fts_def.copy_setting(settings, {})
fts_def.clear(settings)
```

Note that Python does not have direct equivalents for Java's `BooleanSettingsDefinition` and other classes. I've replaced them with simple class definitions.