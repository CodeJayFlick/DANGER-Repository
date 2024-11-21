Here is the translation of the given Java code into Python:

```Python
class SettingsDB:
    def __init__(self, record):
        self.record = record

    def get_name(self):
        return self.record.get_string(SettingsDBAdapter.SETTINGS_NAME_COL)

    def get_long_value(self):
        lvalue = None
        if not self.get_string_value() and not self.get_byte_value():
            lvalue = long(self.record.get_long_value(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL))
        return lvalue

    def get_string_value(self):
        return self.record.get_string(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL)

    def get_byte_value(self):
        return self.record.get_binary_data(SettingsDBAdapter.SETTINGS_BYTE_VALUE_COL)

    def get_value(self):
        obj = self.get_string_value()
        if obj:
            return obj
        obj = self.get_byte_value()
        if obj:
            return obj
        return self.get_long_value()

class SettingsDBAdapter:
    SETTINGS_NAME_COL = None
    SETTINGS_LONG_VALUE_COL = None
    SETTINGS_STRING_VALUE_COL = None
    SETTINGS_BYTE_VALUE_COL = None

# Example usage:

record = DBRecord()  # Replace with your actual record object
settings_db = SettingsDB(record)
print(settings_db.get_name())
```

Please note that this translation assumes the existence of a `DBRecord` class and an `SettingsDBAdapter` class, which are not provided in the original Java code. You would need to implement these classes according to their respective roles in your application.

Also, Python does not have direct equivalents for some Java features like packages, interfaces, or abstract classes. Therefore, this translation focuses on converting the given Java code into equivalent Python syntax and structure.