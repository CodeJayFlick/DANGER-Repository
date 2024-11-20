Here is the translation of the given Java code into Python:

```Python
class BuiltinDBAdapterV0:
    V0_BUILT_IN_TABLE_NAME = "Built-in datatypes"
    V0_ Built_IN_NAME_COL = 0
    V0_ Built_IN_CLASSNAME_COL = 1
    V0_ Built_IN_CAT_COL = 2

    def __init__(self, handle, create):
        if create:
            self.table = handle.create_table(V0_BUILT_IN_TABLE_NAME)
        else:
            try:
                self.table = handle.get_table(V0_BUILT_IN_TABLE_NAME)
            except KeyError as e:
                raise VersionException(f"Missing Table: {V0_BUILT_IN_TABLE_NAME}")

    def get_record(self, data_type_id):
        return self.table.get(data_type_id)

    def get_records_in_category(self, category_id):
        try:
            records = []
            for record in self.table.find_records(category_id, V0_ Built_IN_CAT_COL):
                records.append(record)
            return records
        except KeyError as e:
            raise IOException(f"Error finding records: {e}")

    def update_record(self, record):
        self.table.put(record)

    def remove_record(self, data_type_id):
        try:
            return self.table.delete(data_type_id)
        except KeyError as e:
            raise IOException(f"Error removing record: {e}")

    def create_record(self, name, class_name, category_id):
        table_key = 100
        key = f"{table_key}_{name}"
        record = {"Name": name, "Class Name": class_name, "Category ID": category_id}
        self.table.put(record)
        return record

    def get_records(self):
        try:
            records = []
            for record in self.table.iterate():
                records.append(record)
            return records
        except KeyError as e:
            raise IOException(f"Error iterating over records: {e}")

class VersionException(Exception):
    pass

class IOException(Exception):
    pass
```

Please note that Python does not have direct equivalents of Java's `DBHandle`, `Table`, and other database-related classes. This code is a translation, but it may require additional modifications to work with your specific use case.