Here is the translation of the given Java code into Python:

```Python
class EnumValueDBAdapterV1:
    VERSION = 1
    SCHEMA = {
        "Enum Value ID": {"type": int},
        "Name": {"type": str},
        "Value": {"type": int},
        "Comment": {"type": str}
    }

    def __init__(self, handle, create):
        if create:
            self.table = handle.create_table("ENUM_VALUE_TABLE_NAME", self.SCHEMA)
        else:
            try:
                self.table = handle.get_table("ENUM_VALUE_TABLE_NAME")
                if not self.table:
                    raise VersionException
                version = self.table.schema["version"]
                if version != self.VERSION:
                    msg = f"Expected version {self.VERSION} for table ENUM_VALUE_TABLE_NAME but got {version}"
                    if version < self.VERSION:
                        raise VersionException(msg, "OLDER_VERSION", True)
                    else:
                        raise VersionException(msg, "NEWER_VERSION", False)
            except Exception as e:
                print(f"Error: {e}")

    def create_record(self, enum_id, name, value, comment):
        try:
            record = self.table.create_record()
            record["Enum Value ID"] = enum_id
            record["Name"] = name
            record["Value"] = value
            record["Comment"] = comment
            self.table.put_record(record)
        except Exception as e:
            print(f"Error: {e}")

    def get_record(self, value_id):
        try:
            return self.table.get_record(value_id)
        except Exception as e:
            print(f"Error: {e}")

    def remove_record(self, value_id):
        try:
            self.table.delete_record(value_id)
        except Exception as e:
            print(f"Error: {e}")

    def update_record(self, record):
        try:
            self.table.put_record(record)
        except Exception as e:
            print(f"Error: {e}")

    def get_value_ids_in_enum(self, enum_id):
        try:
            return [r["Enum Value ID"] for r in self.table.find_records({"Enum Value ID": enum_id})]
        except Exception as e:
            print(f"Error: {e}")

    def get_records(self):
        try:
            return iter(self.table)
        except Exception as e:
            print(f"Error: {e}")

class VersionException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `DBHandle`, `Table` and other database-related classes. The above code is a translation, but it may require some modifications to work with your specific use case.