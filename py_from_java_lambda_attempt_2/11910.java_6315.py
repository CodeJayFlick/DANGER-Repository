Here is the translation of the given Java code into Python:

```Python
class SettingsDBAdapterV0:
    V0_SETTINGS_DT_ID_COL = 0
    V0_SETTINGS_NAME_COL = 1
    V0_SETTINGS_LONG_VALUE_COL = 2
    V0_SETTINGS_STRING_VALUE_COL = 3
    V0_SETTINGS_BYTE_VALUE_COL = 4

    V0_SETTINGS_SCHEMA = {
        "Data Type ID": {"type": "long"},
        "Settings Name": {"type": "string"},
        "Long Value": {"type": "long"},
        "String Value": {"type": "string"},
        "Byte Value": {"type": "bytes"}
    }

    def __init__(self, handle, create=False):
        if create:
            self.settings_table = handle.create_table("Settings", V0_SETTINGS_SCHEMA)
        else:
            try:
                self.settings_table = handle.get_table("Settings")
            except KeyError as e:
                raise VersionException(f"Missing Table: {e}")
            if self.settings_table.schema_version != 0:
                raise VersionException(
                    f"Expected version 0 for table 'Settings' but got {self.settings_table.schema_version}"
                )

    def create_settings_record(self, data_type_id, name, str_value, long_value, byte_value):
        record = {"Data Type ID": data_type_id, "Settings Name": name}
        if str_value:
            record["String Value"] = str_value
        else:
            record.pop("String Value", None)
        if long_value is not None:
            record["Long Value"] = long_value
        if byte_value:
            record["Byte Value"] = byte_value

        self.settings_table.put_record(record)

    def get_settings_keys(self, data_type_id):
        return [record for record in self.settings_table.find_records({"Data Type ID": data_type_id})]

    def remove_settings_record(self, settings_id):
        try:
            self.settings_table.delete_record(settings_id)
        except KeyError as e:
            raise VersionException(f"Settings Record {e} not found")

    def get_settings_record(self, settings_id):
        return self.settings_table.get_record(settings_id)

    def update_settings_record(self, record):
        self.settings_table.put_record(record)

    def get_record_count(self):
        return len(list(self.settings_table))

class VersionException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `DBHandle`, `Table` and other database-related classes. The above code is a simple translation, it may need to be adjusted based on the actual database operations you are performing in your application.