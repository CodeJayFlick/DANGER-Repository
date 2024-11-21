Here is the translation of the given Java code into Python:

```Python
class CallingConventionDBAdapterV0:
    CALLING_CONVENTION_TABLE_NAME = "Calling Conventions"
    
    V0_CALLING_CONVENTION_SCHEMA = {
        'ID': {'type': int, 'length': 1},
        'Name': {'type': str}
    }

    def __init__(self, handle, create=False):
        if create:
            self.calling_convention_table = handle.create_table(CALLING_CONVENTION_TABLE_NAME, V0_CALLING_CONVENTION_SCHEMA)
        else:
            try:
                self.calling_convention_table = handle.get_table(CALLING_CONVENTION_TABLE_NAME)
            except KeyError:
                raise VersionException(True)

    def create_calling_convention_record(self, name):
        key = 2
        while True:
            record = {'ID': key}
            for field in V0_CALLING_CONVENTION_SCHEMA.values():
                if isinstance(field['type'], str):
                    record[field] = name
                else:
                    record[field] = key
            self.calling_convention_table.put_record(record)
            return record

    def get_first_available_key(self):
        key = 2
        while True:
            try:
                _ = self.get_calling_convention_record(key)
                if isinstance(_, dict):  # If the result is a dictionary, it means we found an existing record.
                    return key + 1
            except KeyError:  # If there's no such record with this ID, then we can use this ID for our new record.
                return key

    def get_calling_convention_record(self, calling_convention_id):
        try:
            return self.calling_convention_table.get_record(calling_convention_id)
        except KeyError:  # If there's no such record with this ID, then we can't find it.
            raise ValueError("No such record found.")

    def get_calling_convention_record(self, name):
        for record in self.calling_convention_table:
            if record['Name'] == name:
                return record
        return None

class VersionException(Exception):
    pass
```

Please note that Python does not have a direct equivalent to Java's `DBRecord` and `Table`. The above code uses dictionaries as records, which are the basic data structure in Python.