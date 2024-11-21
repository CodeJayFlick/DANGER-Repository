Here is the translation of the given Java code into Python:

```Python
class TypedefDBAdapterV1:
    VERSION = 1
    V1_TYPEDEF_DT_ID_COL = 0
    V1_TYPEDEF_NAME_COL = 1
    V1_TYPEDEF_CAT_COL = 2
    V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL = 3
    V1_TYPEDEF_UNIVERSAL_DT_ID_COL = 4
    V1_TYPEDEF_SOURCE_SYNC_TIME_COL = 5
    V1_TYPEDEF_LAST_CHANGE_TIME_COL = 6

    SCHEMA_V1 = {
        "Typedef ID": {"type": int},
        "Name": {"type": str},
        "Category ID": {"type": int},
        "Source Archive ID": {"type": int},
        "Universal Data Type ID": {"type": int},
        "Source Sync Time": {"type": int},
        "Last Change Time": {"type": int}
    }

    def __init__(self, handle, create):
        if create:
            self.table = handle.create_table("Typedef", self.SCHEMA_V1)
        else:
            try:
                self.table = handle.get_table("Typedef")
            except KeyError as e:
                raise VersionException(f"Missing Table: {e}")
            version = self.table["schema"]["version"]
            if version != self.VERSION:
                msg = f"Expected version {self.VERSION} for table Typedef but got {version}"
                if version < self.VERSION:
                    raise VersionException(msg, "OLDER_VERSION", True)
                else:
                    raise VersionException(msg, "NEWER_VERSION", False)

    def delete_table(self, handle):
        try:
            handle.delete_table("Typedef")
        except KeyError as e:
            print(f"Table not found: {e}")

    def create_record(self, data_type_id, name, category_id, source_archive_id, source_data_type_id, last_change_time):
        record = {"data type ID": data_type_id,
                  "Name": name,
                  "Category ID": category_id,
                  "Source Archive ID": source_archive_id,
                  "Universal Data Type ID": source_data_type_id,
                  "Last Change Time": last_change_time}
        self.table.put(record)
        return record

    def get_record(self, typedef_id):
        try:
            return self.table.get(typedef_id)
        except KeyError as e:
            print(f"Record not found: {e}")

    def get_records(self):
        return list(self.table.values())

    def update_record(self, record, set_last_change_time=False):
        if set_last_change_time:
            record["Last Change Time"] = int((datetime.datetime.now()).timestamp())
        self.table.put(record)

    def remove_record(self, data_id):
        try:
            del self.table[data_id]
        except KeyError as e:
            print(f"Record not found: {e}")

    def get_records_in_category(self, category_id):
        return [record for record in self.table.values() if record["Category ID"] == category_id]

    def get_records_for_source_archive(self, archive_id):
        return [record for record in self.table.values() if record["Source Archive ID"] == archive_id]

    def get_record_with_ids(self, source_id, data_type_id):
        records = [(k, v) for k, v in self.table.items()]
        for key, value in records:
            if value["Universal Data Type ID"] == data_type_id and value["Source Archive ID"] == source_id:
                return value
        return None

class VersionException(Exception):
    def __init__(self, message, version_type=None, is_older=False):
        super().__init__(message)
        self.version_type = version_type
        self.is_older = is_older
```

Please note that Python does not have direct equivalent of Java's `DBHandle`, `Table` and other database-related classes. The above code uses a dictionary to simulate the behavior of these classes, but it may not work exactly as expected in your specific use case.